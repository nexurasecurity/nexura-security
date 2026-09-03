<?php

namespace Nexura_Security;

if ( !defined( 'ABSPATH' ) ) {
    exit;
}
/**
 * Class Two_Factor_Auth
 * 
 * Handles TOTP generation and validation, Recovery Codes, and XML-RPC enforcement.
 */
class Two_Factor_Auth {
    private static $base32_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * Initializes hooks for 2FA UI and Login Interception.
     */
    public function init() {
        // We will no longer show 2FA fields on the default user profile since we have a custom settings page,
        // but we'll leave it in case admins prefer it, pointing them to the Nexura settings page.
        add_action( 'show_user_profile', [$this, 'render_profile_notice'] );
        add_action( 'edit_user_profile', [$this, 'render_profile_notice'] );
        // Intercept Login
        add_action(
            'wp_login',
            [$this, 'intercept_login'],
            10,
            2
        );
        add_action( 'login_form_NEXURA_2fa_verify', [$this, 'handle_2fa_verification_form'] );
        // Setup Verification (Ajax)
        add_action( 'wp_ajax_nexura_verify_2fa_setup', [$this, 'ajax_verify_2fa_setup'] );
        // XML-RPC
        add_filter( 'xmlrpc_call', [$this, 'intercept_xmlrpc'] );
    }

    /**
     * Renders a notice on the WP profile page redirecting to Nexura 2FA Settings.
     */
    public function render_profile_notice( $user ) {
        if ( !current_user_can( 'edit_user', $user->ID ) ) {
            return;
        }
        $url = admin_url( 'admin.php?page=nexura-login-security&tab=2fa' );
        ?>
        <h2><?php 
        esc_html_e( 'Nexura: Two-Factor Authentication', 'nexura-security' );
        ?></h2>
        <p>
            <?php 
        printf( wp_kses( 
            /* translators: %s: URL to the 2FA settings page. */
            __( 'Two-Factor Authentication is managed in the <a href="%s">Nexura 2FA Settings</a>.', 'nexura-security' ),
            [
                'a' => [
                    'href' => [],
                ],
            ]
         ), esc_url( $url ) );
        ?>
        </p>
        <?php 
    }

    /**
     * Generates a random 16-character Base32 secret.
     */
    public function generate_secret() {
        $secret = '';
        for ($i = 0; $i < 16; $i++) {
            $secret .= self::$base32_chars[wp_rand( 0, 31 )];
        }
        return $secret;
    }

    /**
     * Generates 5 random 16-character recovery codes.
     */
    public function generate_recovery_codes() {
        $codes = [];
        for ($i = 0; $i < 5; $i++) {
            $code = wp_generate_password( 16, false, false );
            // Format as xxxx xxxx xxxx xxxx for readability
            $codes[] = strtolower( trim( chunk_split( $code, 4, ' ' ) ) );
        }
        return $codes;
    }

    /**
     * Hashes an array of recovery codes and saves them.
     */
    public function save_recovery_codes( $user_id, $codes ) {
        $hashed = [];
        foreach ( $codes as $code ) {
            $hashed[] = wp_hash_password( str_replace( ' ', '', $code ) );
        }
        update_user_meta( $user_id, 'NEXURA_2fa_recovery_codes', $hashed );
    }

    /**
     * Handles the Ajax request to verify and enable 2FA during setup.
     */
    public function ajax_verify_2fa_setup() {
        check_ajax_referer( 'nexura-admin-ajax-nonce', 'security' );
        if ( !is_user_logged_in() ) {
            wp_send_json_error( [
                'message' => 'Not logged in.',
            ] );
        }
        $code = ( isset( $_POST['code'] ) ? preg_replace( '/[^0-9]/', '', sanitize_text_field( wp_unslash( $_POST['code'] ) ) ) : '' );
        $secret = ( isset( $_POST['secret'] ) ? sanitize_text_field( wp_unslash( $_POST['secret'] ) ) : '' );
        if ( empty( $code ) || empty( $secret ) ) {
            wp_send_json_error( [
                'message' => 'Invalid input.',
            ] );
        }
        $user_id = get_current_user_id();
        if ( $this->verify_code( $secret, $code ) ) {
            update_user_meta( $user_id, 'NEXURA_2fa_enabled', '1' );
            update_user_meta( $user_id, 'NEXURA_2fa_secret', $secret );
            // Generate recovery codes
            $raw_codes = $this->generate_recovery_codes();
            $this->save_recovery_codes( $user_id, $raw_codes );
            wp_send_json_success( [
                'message'        => '2FA Enabled successfully!',
                'recovery_codes' => $raw_codes,
            ] );
        } else {
            wp_send_json_error( [
                'message' => 'Invalid code. Please try again.',
            ] );
        }
    }

    /**
     * Intercepts successful WP logins.
     */
    public function intercept_login( $user_login, $user ) {
        $is_enabled = get_user_meta( $user->ID, 'NEXURA_2fa_enabled', true );
        if ( $is_enabled === '1' ) {
            // Check if device is remembered (Pro feature)
            if ( function_exists( 'nsp_fs' ) ) {
            }
            // Log the user out temporarily and store their ID in a secure transient
            wp_logout();
            $token = wp_generate_password( 32, false );
            set_transient( 'NEXURA_2fa_token_' . $token, $user->ID, 300 );
            // 5 minute validity
            $redirect_url = site_url( 'wp-login.php?action=NEXURA_2fa_verify&token=' . $token );
            if ( isset( $_REQUEST['redirect_to'] ) ) {
                // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                $redirect_url = add_query_arg( 'redirect_to', urlencode( sanitize_text_field( wp_unslash( $_REQUEST['redirect_to'] ) ) ), $redirect_url );
                // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            }
            wp_safe_redirect( $redirect_url );
            exit;
        }
    }

    /**
     * Handles the 2FA verification form on the login page.
     */
    public function handle_2fa_verification_form() {
        $token = ( isset( $_GET['token'] ) ? sanitize_text_field( wp_unslash( $_GET['token'] ) ) : '' );
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if ( empty( $token ) ) {
            wp_die( 'Invalid 2FA token.' );
        }
        $user_id = get_transient( 'NEXURA_2fa_token_' . $token );
        if ( !$user_id ) {
            wp_die( '2FA session expired. Please log in again.' );
        }
        $user = get_userdata( $user_id );
        $error = '';
        if ( isset( $_POST['NEXURA_2fa_code'] ) ) {
            if ( !isset( $_POST['_wpnonce'] ) || !wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'NEXURA_verify_2fa' ) ) {
                wp_die( 'Security check failed.' );
            }
            $raw_code = sanitize_text_field( wp_unslash( $_POST['NEXURA_2fa_code'] ) );
            $code = preg_replace( '/[^0-9a-zA-Z]/', '', $raw_code );
            // Allow letters for recovery codes
            $secret = get_user_meta( $user->ID, 'NEXURA_2fa_secret', true );
            $is_valid = false;
            // Try TOTP
            if ( strlen( $code ) === 6 && preg_match( '/^[0-9]+$/', $code ) && $this->verify_code( $secret, $code ) ) {
                $is_valid = true;
            } else {
                // Try Recovery Code
                $recovery_codes = get_user_meta( $user->ID, 'NEXURA_2fa_recovery_codes', true );
                if ( is_array( $recovery_codes ) ) {
                    foreach ( $recovery_codes as $index => $hash ) {
                        if ( wp_check_password( strtolower( $code ), $hash, $user->ID ) ) {
                            $is_valid = true;
                            // Consume the code
                            unset($recovery_codes[$index]);
                            update_user_meta( $user->ID, 'NEXURA_2fa_recovery_codes', array_values( $recovery_codes ) );
                            break;
                        }
                    }
                }
            }
            if ( $is_valid ) {
                // Clear token and attempts
                delete_transient( 'NEXURA_2fa_token_' . $token );
                delete_transient( 'NEXURA_2fa_attempts_' . $token );
                // Handle Remember Device (Pro feature)
                if ( function_exists( 'nsp_fs' ) ) {
                }
                // Log user in
                wp_set_current_user( $user->ID, $user->user_login );
                wp_set_auth_cookie( $user->ID, true );
                do_action( 'wp_login', $user->user_login, $user );
                // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
                // SECURITY FIX: Validate redirect URL is same-site to prevent Open Redirect attacks
                $raw_redirect = ( isset( $_REQUEST['redirect_to'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['redirect_to'] ) ) : admin_url() );
                // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                $redirect_to = wp_validate_redirect( $raw_redirect, admin_url() );
                wp_safe_redirect( $redirect_to );
                exit;
            } else {
                $attempts = (int) get_transient( 'NEXURA_2fa_attempts_' . $token );
                $attempts++;
                if ( $attempts >= 3 ) {
                    delete_transient( 'NEXURA_2fa_token_' . $token );
                    delete_transient( 'NEXURA_2fa_attempts_' . $token );
                    wp_die( 'Too many failed 2FA attempts. Session locked. Please log in again.' );
                }
                set_transient( 'NEXURA_2fa_attempts_' . $token, $attempts, 300 );
                $error = 'Invalid code. You have ' . (3 - $attempts) . ' attempts left.';
            }
        }
        // Output the 2FA form
        login_header( 'Two-Factor Authentication', '', new \WP_Error('2fa_failed', $error) );
        ?>
        <form name="NEXURA_2fa_form" id="NEXURA_2fa_form" action="" method="post">
            <?php 
        wp_nonce_field( 'NEXURA_verify_2fa' );
        ?>
            <p>
                <label for="NEXURA_2fa_code"><?php 
        esc_html_e( 'Authentication Code or Recovery Code', 'nexura-security' );
        ?><br />
                <input type="text" name="NEXURA_2fa_code" id="NEXURA_2fa_code" class="input" value="" size="20" autocomplete="one-time-code" autofocus /></label>
            </p>
            <?php 
        if ( function_exists( 'nsp_fs' ) ) {
            ?>
                <?php 
            ?>
            <?php 
        }
        ?>
            <?php 
        if ( isset( $_REQUEST['redirect_to'] ) ) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            ?>
                <input type="hidden" name="redirect_to" value="<?php 
            echo esc_url( sanitize_text_field( wp_unslash( $_REQUEST['redirect_to'] ) ) );
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            ?>" />
            <?php 
        }
        ?>
            <p class="submit">
                <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="<?php 
        esc_attr_e( 'Verify', 'nexura-security' );
        ?>" />
            </p>
        </form>
        <?php 
        login_footer();
        exit;
    }

    /**
     * Intercepts XML-RPC calls to enforce 2FA and settings.
     */
    public function intercept_xmlrpc( $method ) {
        // We only enforce this if XML-RPC is processed.
        $disable_xmlrpc = get_option( 'NEXURA_disable_xmlrpc', '0' );
        if ( $disable_xmlrpc === '1' ) {
            wp_die( 'XML-RPC is disabled.', 'XML-RPC Disabled', 403 );
        }
        $require_xmlrpc_2fa = get_option( 'NEXURA_require_xmlrpc_2fa', '0' );
        if ( $require_xmlrpc_2fa === '1' ) {
            // WordPress authenticates the user before firing most XML-RPC methods via application passwords or normal passwords.
            // If the user has 2FA enabled, they must use an Application Password.
            $user = wp_get_current_user();
            if ( $user && $user->exists() ) {
                $is_enabled = get_user_meta( $user->ID, 'NEXURA_2fa_enabled', true );
                if ( $is_enabled === '1' && !did_action( 'application_password_did_authenticate' ) ) {
                    wp_die( 'Two-Factor Authentication is enabled for your account. You must use an Application Password for XML-RPC requests.', '2FA Required', 403 );
                }
            }
        }
        return $method;
    }

    /**
     * Gets the current time, adjusted with NTP offset if enabled.
     */
    private function get_current_time() {
        // NTP sync is opt-in only (default OFF).
        // Satisfies WordPress.org Guidelines 7 & 9: no remote calls without consent.
        if ( get_option( 'NEXURA_ntp_sync', '0' ) !== '1' ) {
            return current_time( 'timestamp', true );
        }
        $offset = get_transient( 'NEXURA_ntp_offset' );
        if ( $offset === false ) {
            // We use the Date header from a reliable fast service to avoid rate limits
            $response = wp_remote_head( 'https://google.com', [
                'timeout' => 3,
            ] );
            if ( !is_wp_error( $response ) ) {
                $date_header = wp_remote_retrieve_header( $response, 'date' );
                if ( !empty( $date_header ) ) {
                    $server_time = strtotime( $date_header );
                    $offset = $server_time - current_time( 'timestamp', true );
                    set_transient( 'NEXURA_ntp_offset', $offset, 12 * HOUR_IN_SECONDS );
                } else {
                    $offset = 0;
                }
            } else {
                $offset = 0;
            }
        }
        return current_time( 'timestamp', true ) + (int) $offset;
    }

    /**
     * Verifies a 6-digit TOTP code against a Base32 secret.
     */
    public function verify_code( $secret, $code ) {
        if ( empty( $secret ) || empty( $code ) || strlen( $code ) !== 6 ) {
            return false;
        }
        $current_time = $this->get_current_time();
        $time_step = floor( $current_time / 30 );
        // Allow 1 step before and 1 step after for clock drift (90 seconds total window)
        for ($i = -1; $i <= 1; $i++) {
            if ( hash_equals( (string) $this->get_totp_code( $secret, $time_step + $i ), (string) $code ) ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Generates a TOTP code for a specific time step.
     */
    private function get_totp_code( $secret, $time_step ) {
        $secret_binary = $this->base32_decode( $secret );
        $time_binary = pack( 'N*', 0 ) . pack( 'N*', $time_step );
        $hash = hash_hmac(
            'sha1',
            $time_binary,
            $secret_binary,
            true
        );
        $offset = ord( substr( $hash, -1 ) ) & 0xf;
        $hash_part = substr( $hash, $offset, 4 );
        $value = unpack( 'N', $hash_part );
        $value = $value[1] & 0x7fffffff;
        $modulo = pow( 10, 6 );
        return str_pad(
            $value % $modulo,
            6,
            '0',
            STR_PAD_LEFT
        );
    }

    /**
     * Decodes a Base32 string.
     */
    private function base32_decode( $secret ) {
        if ( empty( $secret ) ) {
            return '';
        }
        $secret = strtoupper( $secret );
        $binary = '';
        $allowed_values = array(
            'A' => 0,
            'B' => 1,
            'C' => 2,
            'D' => 3,
            'E' => 4,
            'F' => 5,
            'G' => 6,
            'H' => 7,
            'I' => 8,
            'J' => 9,
            'K' => 10,
            'L' => 11,
            'M' => 12,
            'N' => 13,
            'O' => 14,
            'P' => 15,
            'Q' => 16,
            'R' => 17,
            'S' => 18,
            'T' => 19,
            'U' => 20,
            'V' => 21,
            'W' => 22,
            'X' => 23,
            'Y' => 24,
            'Z' => 25,
            '2' => 26,
            '3' => 27,
            '4' => 28,
            '5' => 29,
            '6' => 30,
            '7' => 31,
        );
        foreach ( str_split( str_replace( '=', '', $secret ) ) as $char ) {
            if ( !isset( $allowed_values[$char] ) ) {
                continue;
            }
            $binary .= str_pad(
                decbin( $allowed_values[$char] ),
                5,
                '0',
                STR_PAD_LEFT
            );
        }
        $decoded = '';
        foreach ( str_split( $binary, 8 ) as $chunk ) {
            if ( strlen( $chunk ) === 8 ) {
                $decoded .= chr( bindec( $chunk ) );
            }
        }
        return $decoded;
    }

}
