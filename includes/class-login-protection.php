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

    private $max_attempts = 5;
    private $lockout_duration = 1800; // 30 minutes

    public function __construct() {
        // Hooks moved to init() for architectural consistency and proper initialization lifecycle.
    }

    /**
     * Initializes hooks.
     */
    public function init() {
        add_filter( 'authenticate', [ $this, 'check_login_attempts' ], 30, 3 );
        add_action( 'wp_login_failed', [ $this, 'log_failed_attempt' ] );

        // Custom Login URL hooks
        add_action( 'init', [ $this, 'handle_custom_login_route' ] );
        add_action( 'init', [ $this, 'block_wp_admin' ] ); // Block wp-admin access to prevent leaking custom URL
        add_action( 'setup_theme', [ $this, 'redirect_default_login' ], 1 ); // Early hook
        add_filter( 'site_url', [ $this, 'filter_site_url' ], 10, 4 );
        add_filter( 'network_site_url', [ $this, 'filter_site_url' ], 10, 3 );
        add_filter( 'wp_redirect', [ $this, 'filter_wp_redirect' ], 10, 2 );

        // Branding
        add_action( 'login_footer', [ $this, 'add_login_branding' ] );
    }

    /**
     * Checks if the user's IP is locked out before authentication.
     */
    public function check_login_attempts( $user, $username, $password ) {
        $ip = $this->get_client_ip();
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
        $attempts = get_transient( 'NEXURA_login_attempts_' . $ip );

        if ( $attempts === false ) {
            $attempts = 1;
        } else {
            $attempts++;
        }

        set_transient( 'NEXURA_login_attempts_' . $ip, $attempts, $this->lockout_duration );

        if ( $attempts >= $this->max_attempts ) {
        if ( class_exists( '\Nexura_Security\Logger' ) ) {
            Logger::log( 'Brute Force Blocked: IP ' . $ip . ' locked out after ' . $attempts . ' failed attempts.' );
        }
            if ( class_exists( '\Nexura_Security\Global_Threat_Intel' ) ) {
                (new \Nexura_Security\Global_Threat_Intel())->report_ip( 'brute_force_login' );
            }
        }
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

        // Check if accessing wp-login.php
        if ( strpos( $path, 'wp-login.php' ) !== false && ! is_user_logged_in() ) {
            // Allow POST requests to wp-login.php (to allow actual login processing from our custom page)
            if ( isset( $_SERVER['REQUEST_METHOD'] ) && $_SERVER['REQUEST_METHOD'] === 'POST' ) {
                return;
            }

            // Redirect to a non-existent URL to trigger the theme's native 404 page
            wp_safe_redirect( home_url( '404' ) );
            exit;
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

        // If accessing wp-admin while logged out, throw 404 (except for ajax/post endpoints)
        if ( strpos( $path, '/wp-admin' ) !== false && ! is_user_logged_in() ) {
            $basename = basename( $path );
            if ( ! in_array( $basename, [ 'admin-ajax.php', 'admin-post.php' ], true ) ) {
                // Redirect to a non-existent URL to trigger the theme's native 404 page
                wp_safe_redirect( home_url( '404' ) );
                exit;
            }
        }
    }

    /**
     * Adds branding to the login page footer.
     */
    public function add_login_branding() {
        echo '<p style="text-align: center; margin-top: 20px; color: #50575e; font-size: 13px; display: flex; align-items: center; justify-content: center; gap: 6px;"><img src="' . esc_url( NEXURA_PLUGIN_URL . 'admin/img/icon.png' ) . '" alt="Nexura Icon" style="width: 14px; height: 14px; opacity: 0.7;">Nexura Security Protected</p>';
    }
}
