<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Login_Protection
 * 
 * Limits login attempts and blocks brute-force attacks.
 */
class Login_Protection {

    private $max_attempts;
    private $lockout_duration;

    public function __construct() {
        $this->max_attempts = max( 1, (int) get_option( 'NEXURA_brute_force_max_attempts', 5 ) );
        $this->lockout_duration = (int) get_option( 'NEXURA_brute_force_lockout', 1800 ); // Default 30 mins
    }

    /**
     * Initializes hooks.
     */
    public function init() {
        add_filter( 'authenticate', [ $this, 'check_login_attempts' ], 30, 3 );
        add_action( 'wp_login_failed', [ $this, 'log_failed_attempt' ] );
        add_action( 'xmlrpc_login_error', [ $this, 'log_failed_xmlrpc_attempt' ], 10, 2 );
        add_filter( 'rest_authentication_errors', [ $this, 'track_rest_auth_failures' ], 999 );

        // Custom Login URL hooks
        add_action( 'init', [ $this, 'handle_custom_login_route' ] );
        add_action( 'init', [ $this, 'block_wp_admin' ] ); // Block wp-admin access to prevent leaking custom URL
        add_action( 'setup_theme', [ $this, 'redirect_default_login' ], 1 ); // Early hook
        add_filter( 'site_url', [ $this, 'filter_site_url' ], 10, 4 );
        add_filter( 'network_site_url', [ $this, 'filter_site_url' ], 10, 3 );
        add_filter( 'wp_redirect', [ $this, 'filter_wp_redirect' ], 10, 2 );

        // Branding
        add_action( 'login_footer', [ $this, 'add_login_branding' ] );

        // Lockout countdown timer — shown natively within WP errors via login_errors filter at high priority
        add_filter( 'login_errors', [ $this, 'show_lockout_countdown' ], 999 );
        add_action( 'login_enqueue_scripts', [ $this, 'enqueue_lockout_scripts' ] );
        add_action( 'wp_enqueue_scripts', [ $this, 'enqueue_lockout_scripts' ] );

        // Clear IP lockouts on successful login or password reset
        add_action( 'wp_login', [ $this, 'clear_ip_lockout' ] );
        add_action( 'after_password_reset', [ $this, 'clear_ip_lockout' ] );

        // Add warning message to failed login attempts
        // Removed: Handled natively inside show_lockout_countdown via login_errors filter
    }

    /**
     * Clears the lockout transients for the current IP upon successful login or password reset.
     */
    public function clear_ip_lockout() {
        $ip = $this->get_client_ip();
        delete_transient( 'NEXURA_login_attempts_' . $ip );
        delete_transient( 'NEXURA_lockout_expiry_' . $ip );
        delete_transient( 'NEXURA_lockout_strike_' . $ip );
        delete_transient( 'NEXURA_lockout_data_' . $ip );
    }

    /**
     * Obsolete: Replaced by show_lockout_countdown hooking into login_errors
     */
    public function add_login_warning_message( $user, $username, $password ) {
        return $user;
    }

    /**
     * Checks if the user's IP is locked out before authentication.
     */
    public function check_login_attempts( $user, $username, $password ) {
        $ip = $this->get_client_ip();

        // Always allow localhost in local/dev environments — never lock out developer.
        // On a live server, real visitors can never have these IPs, so this is safe.
        // To test lockout/countdown on localhost, add this to wp-config.php:
        //   define( 'NEXURA_FORCE_LOCKOUT_TEST', true );
        $force_test = defined( 'NEXURA_FORCE_LOCKOUT_TEST' ) && NEXURA_FORCE_LOCKOUT_TEST;
        $is_local   = ! $force_test && in_array( $ip, [ '127.0.0.1', '::1' ], true ) && (
            defined( 'WP_DEBUG' ) && WP_DEBUG ||
            strpos( site_url(), 'localhost' ) !== false ||
            strpos( site_url(), '127.0.0.1' ) !== false
        );
        if ( $is_local ) {
            return $user;
        }

        // Check whether the previous lockout has expired.
        $expiry = get_transient( 'NEXURA_lockout_expiry_' . $ip );

        if ( false !== $expiry && $expiry <= time() ) {
            // Lockout expired — start a fresh attempt window.
            delete_transient( 'NEXURA_lockout_expiry_' . $ip );
            delete_transient( 'NEXURA_lockout_data_' . $ip );
            delete_transient( 'NEXURA_login_attempts_' . $ip );
        }

        // Check current attempts after resetting an expired lockout.
        $attempts = get_transient( 'NEXURA_login_attempts_' . $ip );

        if ( $attempts !== false && $attempts >= $this->max_attempts ) {
            return new \WP_Error( 'too_many_retries', wp_kses_post( __( '<strong>ERROR</strong>: Too many failed login attempts. Please try again later.', 'nexura-security' ) ) );
        }

        return $user;
    }

    /**
     * Records a failed login attempt.
     */
    public function log_failed_attempt( $username ) {
        $ip = $this->get_client_ip();
        
        // If the previous lockout has expired, reset the attempt counter.
        $expiry = get_transient( 'NEXURA_lockout_expiry_' . $ip );

        if ( false !== $expiry && $expiry <= time() ) {
            delete_transient( 'NEXURA_lockout_expiry_' . $ip );
            delete_transient( 'NEXURA_lockout_data_' . $ip );
            delete_transient( 'NEXURA_login_attempts_' . $ip );
        }

        // If IP is currently locked out, do not increment attempts.
        $expiry = get_transient( 'NEXURA_lockout_expiry_' . $ip );

        if ( false !== $expiry && $expiry > time() ) {
            return;
        }

        $attempts = get_transient( 'NEXURA_login_attempts_' . $ip );

        if ( $attempts === false ) {
            $attempts = 1;
        } else {
            $attempts++;
        }

        set_transient( 'NEXURA_login_attempts_' . $ip, $attempts, 24 * HOUR_IN_SECONDS );

        if ( $attempts >= $this->max_attempts ) {
            
            $strike = get_transient( 'NEXURA_lockout_strike_' . $ip );
            if ( $strike === false ) {
                $strike = 1;
            } else {
                $strike++;
            }
            
            if ( $strike === 1 ) {
                $duration = 10 * MINUTE_IN_SECONDS;
            } elseif ( $strike === 2 ) {
                $duration = 30 * MINUTE_IN_SECONDS;
            } elseif ( $strike === 3 ) {
                $duration = 60 * MINUTE_IN_SECONDS;
            } else {
                // 4th strike and beyond: 24 hour block
                $duration = 24 * HOUR_IN_SECONDS;
            }
            
            // Keep strike history for 24 hours. If they stay clean for 24 hours, their strike level resets.
            set_transient( 'NEXURA_lockout_strike_' . $ip, $strike, 24 * HOUR_IN_SECONDS );

            // Store the exact expiry timestamp so the login page countdown timer knows when it lifts.
            $expiry = time() + $duration;
            set_transient( 'NEXURA_lockout_expiry_' . $ip, $expiry, $duration );

            // Store additional data for the Locked IPs admin UI
            $lockout_data = [
                'username' => sanitize_user( $username ),
                'strike'   => $strike,
                'time'     => time(),
                'duration' => $duration
            ];
            set_transient( 'NEXURA_lockout_data_' . $ip, $lockout_data, $duration );

            if ( class_exists( '\Nexura_Security\Logger' ) ) {
                Logger::log( 'Brute Force Blocked: IP ' . $ip . ' locked out (Strike ' . $strike . ') after ' . $attempts . ' failed attempts.' );
            }
            if ( class_exists( '\Nexura_Security\Attack_Logger' ) ) {
                \Nexura_Security\Attack_Logger::log_attack( $ip, 'Brute Force Attack', 'Locked Out (Strike ' . $strike . ')' );
            }
            if ( class_exists( '\Nexura_Security\Global_Threat_Intel' ) ) {
                (new \Nexura_Security\Global_Threat_Intel())->report_ip( 'brute_force_login' );
            }
            // Send instant security alert
            Alert_System::send_alert(
                'Brute Force Attack — IP Locked Out',
                sprintf( 'IP address %s has been locked out after %d failed login attempts (Strike level: %d). Target username: "%s".', $ip, $attempts, $strike, $username ),
                'high'
            );
        }
    }

    /**
     * Records a failed XML-RPC login attempt.
     */
    public function log_failed_xmlrpc_attempt( $error, $user ) {
        // user could be an object or string depending on the exact WP version, just log the attempt
        $username = is_object($user) ? $user->user_login : (string) $user;
        $this->log_failed_attempt( $username );
    }

    /**
     * Tracks failed REST API authentications.
     */
    public function track_rest_auth_failures( $result ) {
        // If the user is already successfully logged in, don't block them or log failures.
        if ( is_user_logged_in() || $result === true ) {
            return $result;
        }
        
        $ip = $this->get_client_ip();
        
        // Always allow localhost in local/dev environments
        $is_local = in_array( $ip, [ '127.0.0.1', '::1' ], true ) && (
            ( defined( 'WP_DEBUG' ) && WP_DEBUG ) ||
            strpos( site_url(), 'localhost' ) !== false ||
            strpos( site_url(), '127.0.0.1' ) !== false
        );
        if ( $is_local ) {
            return $result;
        }

        if ( is_wp_error( $result ) ) {
            // Do not log invalid nonces as brute force attacks
            if ( $result->get_error_code() === 'incorrect_password' || $result->get_error_code() === 'invalid_username' ) {
                $this->log_failed_attempt( 'rest_api' );
            }
        }
        
        // Also check if the IP is already locked out to block the request early
        $ip = $this->get_client_ip();
        $expiry = get_transient( 'NEXURA_lockout_expiry_' . $ip );
        if ( $expiry !== false && $expiry > time() ) {
            // Bypass lockout for public tracking endpoint
            if ( isset( $_SERVER['REQUEST_URI'] ) && strpos( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ), '/nexura/v1/track' ) !== false ) {
                return $result;
            }
            return new \WP_Error( 'too_many_retries', __( 'Too many failed authentication attempts. Please try again later.', 'nexura-security' ), array( 'status' => 401 ) );
        }

        return $result;
    }

    /**
     * Helper to get client IP.
     */
    private function get_client_ip() {
        $ip = isset( $_SERVER['REMOTE_ADDR'] ) ? preg_replace( '/[^0-9a-fA-F:., ]/', '', sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) ) : '127.0.0.1';
        
        if ( isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && $this->is_cloudflare_ip( $ip ) ) {
            $cf_ip = preg_replace( '/[^0-9a-fA-F:., ]/', '', sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) );
            if ( filter_var( $cf_ip, FILTER_VALIDATE_IP ) ) {
                $ip = $cf_ip;
            }
        }
        
        return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '127.0.0.1';
    }

    /**
     * Checks if the given IP address is a Cloudflare IP.
     */
    private function is_cloudflare_ip( $ip ) {
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
            return false;
        }
        
        $cf_ips = [];
        $log_dir = wp_upload_dir()['basedir'] . '/nexura-security';
        $cf_file = $log_dir . '/cloudflare-ips.php';
        if ( file_exists( $cf_file ) ) {
            $cf_ips = include $cf_file;
        }
        
        if ( empty( $cf_ips ) || ! is_array( $cf_ips ) ) {
            $cf_ips = [
                '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
                '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
                '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
                '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
            ];
        }
        
        $ip_long = ip2long( $ip );
        foreach ( $cf_ips as $cidr ) {
            if ( strpos( $cidr, '/' ) === false ) {
                continue;
            }
            list( $subnet, $bits ) = explode( '/', $cidr );
            $subnet_long = ip2long( $subnet );
            $mask = -1 << ( 32 - $bits );
            $subnet_long &= $mask;
            if ( ( $ip_long & $mask ) === $subnet_long ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Handles the routing if the user accesses the custom login slug.
     */
    public function handle_custom_login_route() {
        $custom_slug = get_option( 'NEXURA_custom_login_slug' );
        if ( empty( $custom_slug ) ) {
            return;
        }

        $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
        $parsed_uri = wp_parse_url( $request_uri );
        $path = isset( $parsed_uri['path'] ) ? untrailingslashit( $parsed_uri['path'] ) : '';
        
        $site_path = wp_parse_url( site_url(), PHP_URL_PATH );
        if ( $site_path ) {
            $path = preg_replace( '|^' . preg_quote( $site_path, '|' ) . '|i', '', $path );
        }
        $path = ltrim( $path, '/' );

        if ( $path === $custom_slug ) {
            global $pagenow, $error, $interim_login, $action, $user_login;
            $pagenow = 'wp-login.php';
            $_SERVER['REQUEST_URI'] = $this->get_relative_path( 'wp-login.php' ) . ( isset( $parsed_uri['query'] ) ? '?' . $parsed_uri['query'] : '' );
            @require_once ABSPATH . 'wp-login.php';
            exit;
        }
    }

    /**
     * Redirects users away from the default wp-login.php if a custom slug is set.
     */
    public function redirect_default_login() {
        $custom_slug = get_option( 'NEXURA_custom_login_slug' );
        if ( empty( $custom_slug ) ) {
            return;
        }

        $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
        $parsed_uri = wp_parse_url( $request_uri );
        $path = isset( $parsed_uri['path'] ) ? untrailingslashit( $parsed_uri['path'] ) : '';

        // Block ALL access (GET and POST) to wp-login.php when a custom slug is configured.
        // This closes the bypass where a hacker could POST directly to wp-login.php.
        if ( strpos( $path, 'wp-login.php' ) !== false && ! is_user_logged_in() ) {
            // Allow only action=NEXURA_2fa_verify so our own 2FA flow continues to work.
            $action = isset( $_GET['action'] ) ? sanitize_key( wp_unslash( $_GET['action'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            if ( $action === 'NEXURA_2fa_verify' ) {
                return;
            }

            // Also allow password reset actions — users need these links from email.
            $allowed_actions = [ 'rp', 'resetpass', 'lostpassword' ];
            if ( in_array( $action, $allowed_actions, true ) ) {
                return;
            }

            // Return a proper 403 Forbidden instead of redirecting to a page that may not exist.
            status_header( 403 );
            wp_die(
                esc_html__( 'Access to this page has been restricted.', 'nexura-security' ),
                esc_html__( 'Forbidden', 'nexura-security' ),
                [ 'response' => 403 ]
            );
        }
    }

    /**
     * Filters site URLs to replace wp-login.php with the custom slug.
     */
    public function filter_site_url( $url, $path, $scheme, $blog_id = null ) {
        $custom_slug = get_option( 'NEXURA_custom_login_slug' );
        if ( empty( $custom_slug ) ) {
            return $url;
        }

        if ( strpos( $url, 'wp-login.php' ) !== false ) {
            $url = str_replace( 'wp-login.php', $custom_slug, $url );
        }

        return $url;
    }

    /**
     * Filters redirects to ensure wp-login.php is replaced.
     */
    public function filter_wp_redirect( $location, $status ) {
        $custom_slug = get_option( 'NEXURA_custom_login_slug' );
        if ( empty( $custom_slug ) ) {
            return $location;
        }

        if ( strpos( $location, 'wp-login.php' ) !== false ) {
            $location = str_replace( 'wp-login.php', $custom_slug, $location );
        }

        return $location;
    }

    /**
     * Helper to get relative path for the server variable.
     */
    private function get_relative_path( $path ) {
        $site_path = wp_parse_url( site_url(), PHP_URL_PATH );
        if ( $site_path ) {
            return rtrim( $site_path, '/' ) . '/' . ltrim( $path, '/' );
        }
        return '/' . ltrim( $path, '/' );
    }

    /**
     * Blocks unauthenticated access to wp-admin to prevent leaking the custom login URL via redirect.
     */
    public function block_wp_admin() {
        $custom_slug = get_option( 'NEXURA_custom_login_slug' );
        if ( empty( $custom_slug ) ) {
            return;
        }

        $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
        $parsed_uri = wp_parse_url( $request_uri );
        $path = isset( $parsed_uri['path'] ) ? untrailingslashit( $parsed_uri['path'] ) : '';

        // If accessing wp-admin while logged out, return 403 (except for ajax/post endpoints)
        if ( strpos( $path, '/wp-admin' ) !== false && ! is_user_logged_in() ) {
            $basename = basename( $path );
            if ( ! in_array( $basename, [ 'admin-ajax.php', 'admin-post.php' ], true ) ) {
                status_header( 403 );
                wp_die(
                    esc_html__( 'Access to this page has been restricted.', 'nexura-security' ),
                    esc_html__( 'Forbidden', 'nexura-security' ),
                    [ 'response' => 403 ]
                );
            }
        }
    }

    /**
     * Adds branding to the login page footer.
     */
    public function add_login_branding() {
        echo '<p style="text-align: center; margin-top: 20px; color: #50575e; font-size: 13px; display: flex; align-items: center; justify-content: center; gap: 6px;"><img src="' . esc_url( NEXURA_PLUGIN_URL . 'admin/img/icon.png' ) . '" alt="Nexura Icon" style="width: 14px; height: 14px; opacity: 0.7;">Nexura Security Protected</p>';
    }

    /**
     * Injects a real-time countdown banner into the native WordPress error box when the visitor's
     * IP is locked out. Uses the login_errors filter at high priority to override other plugins.
     *
     * @param  string $error_string Existing login page errors HTML.
     * @return string               Modified error string.
     */
    public function show_lockout_countdown( $error_string ) {
        $ip     = $this->get_client_ip();
        $expiry = get_transient( 'NEXURA_lockout_expiry_' . $ip );

        // If not locked out, check if we need to show a warning about remaining attempts
        if ( false === $expiry || $expiry <= time() ) {
            
            // Only show warning if there's an actual error being displayed (like incorrect password)
            if ( ! empty( $error_string ) ) {
                $attempts = get_transient( 'NEXURA_login_attempts_' . $ip );
                if ( $attempts !== false && $attempts > 0 ) {
                    $remaining = $this->max_attempts - $attempts;
                    if ( $remaining > 0 ) {
                        $warning_msg = sprintf( __( 'Warning: You have %d attempts remaining before your IP is temporarily blocked.', 'nexura-security' ), $remaining );
                        return $error_string . '<br><br><strong>' . esc_html( $warning_msg ) . '</strong>';
                    }
                }
            }
            return $error_string;
        }

        $seconds_remaining = (int) $expiry - time();
        if ( $seconds_remaining <= 0 ) {
            return $error_string;
        }

        $strike = get_transient( 'NEXURA_lockout_strike_' . $ip );
        if ( $strike === false ) {
            $strike = 1;
        } else {
            $strike = (int) $strike;
        }
        
        if ( $strike === 1 ) {
            $lockout_minutes = 10;
        } elseif ( $strike === 2 ) {
            $lockout_minutes = 30;
        } elseif ( $strike === 3 ) {
            $lockout_minutes = 60;
        } else {
            $lockout_minutes = 24 * 60;
        }

        /* translators: %1$d: number of minutes, %2$d: current strike level */
        $blocked_msg = sprintf(
            esc_html__( 'Your IP has been temporarily blocked for %1$d minutes due to too many failed login attempts (Strike %2$d).', 'nexura-security' ),
            $lockout_minutes,
            $strike
        );
        $try_again_msg   = esc_html__( 'You can try again in:', 'nexura-security' );
        $auto_unlock_msg = esc_html__( 'The page will reload automatically when the block is lifted.', 'nexura-security' );

        ob_start();
        ?>
        <?php echo esc_html( $blocked_msg ); ?><br><br>
        <?php echo esc_html( $try_again_msg ); ?> <strong id="nexura-countdown">--:--</strong><br>
        <span style="font-size: 12px; color: #666;"><?php echo esc_html( $auto_unlock_msg ); ?></span>
        <?php
        
        // Completely replace any existing error (e.g. "Invalid login credentials") with our lockout UI
        return ob_get_clean();
    }

    /**
     * Enqueues the countdown JavaScript using standard WordPress APIs.
     */
    public function enqueue_lockout_scripts() {
        $ip     = $this->get_client_ip();
        $expiry = get_transient( 'NEXURA_lockout_expiry_' . $ip );

        if ( false === $expiry ) {
            return;
        }

        $seconds_remaining = (int) $expiry - time();
        if ( $seconds_remaining <= 0 ) {
            return;
        }

        wp_register_script( 'nexura-lockout-js', false );
        wp_enqueue_script( 'nexura-lockout-js' );

        $script = "
        document.addEventListener('DOMContentLoaded', function() {
            var expiry = " . (int) $expiry . ";
            var el     = document.getElementById('nexura-countdown');
            if ( ! el ) return;

            function pad(n) { return n < 10 ? '0' + n : n; }

            function tick() {
                var now  = Math.floor(Date.now() / 1000);
                var diff = expiry - now;
                if ( diff <= 0 ) {
                    el.textContent = '00:00';
                    // Force a clean GET request to the base URL to avoid re-triggering any authentication payload
                    window.location.href = window.location.pathname;
                    return;
                }
                
                var h = Math.floor(diff / 3600);
                var m = Math.floor((diff % 3600) / 60);
                var s = diff % 60;
                
                if (h > 0) {
                    el.textContent = pad(h) + ':' + pad(m) + ':' + pad(s);
                } else {
                    el.textContent = pad(m) + ':' + pad(s);
                }
            }

            tick();
            setInterval(tick, 1000);
        });
        ";
        wp_add_inline_script( 'nexura-lockout-js', $script );
    }
}
