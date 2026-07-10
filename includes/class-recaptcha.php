<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class reCAPTCHA
 * 
 * Handles Google reCAPTCHA v3 verification during login and registration.
 */
class reCAPTCHA {

    /**
     * Initializes hooks.
     */
    public function init() {
        $is_enabled = get_option( 'NEXURA_recaptcha_enabled', '0' );
        if ( $is_enabled !== '1' ) {
            return;
        }

        // Add reCAPTCHA script to login and registration pages
        add_action( 'login_enqueue_scripts', [ $this, 'enqueue_scripts' ] );
        add_action( 'wp_enqueue_scripts', [ $this, 'enqueue_scripts' ] ); // For frontend logins/registrations (e.g. WooCommerce)

        // Inject hidden field in forms
        add_action( 'login_form', [ $this, 'render_field' ] );
        add_action( 'register_form', [ $this, 'render_field' ] );
        add_action( 'woocommerce_login_form', [ $this, 'render_field' ] );
        add_action( 'woocommerce_register_form', [ $this, 'render_field' ] );

        // Authenticate hooks
        add_filter( 'authenticate', [ $this, 'verify_login' ], 20, 3 );
        add_filter( 'registration_errors', [ $this, 'verify_registration' ], 10, 3 );
    }

    /**
     * Enqueues the reCAPTCHA JS.
     */
    public function enqueue_scripts() {
        $site_key = get_option( 'NEXURA_recaptcha_site_key', '' );
        if ( empty( $site_key ) ) {
            return;
        }

        // google.com/recaptcha is only loaded when NEXURA_recaptcha_enabled = '1'
        // (set explicitly by the administrator). This entire class is gated in init().
        // phpcs:ignore PluginCheck.CodeAnalysis.EnqueuedResourceOffloading.OffloadedContent
        wp_enqueue_script( 'nexura-recaptcha-api', 'https://www.google.com/recaptcha/api.js?render=' . esc_attr( $site_key ), [], '3.0', true );
        
        $inline_script = "
        document.addEventListener('DOMContentLoaded', function() {
            var forms = document.querySelectorAll('form#loginform, form#registerform, form.woocommerce-form-login, form.woocommerce-form-register');
            forms.forEach(function(form) {
                form.addEventListener('submit', function(e) {
                    if ( ! form.querySelector('input[name=\"nexura_recaptcha_token\"]') ) {
                        e.preventDefault();
                        grecaptcha.ready(function() {
                            grecaptcha.execute('" . esc_js( $site_key ) . "', {action: 'submit'}).then(function(token) {
                                var input = document.createElement('input');
                                input.type = 'hidden';
                                input.name = 'nexura_recaptcha_token';
                                input.value = token;
                                form.appendChild(input);
                                form.submit();
                            });
                        });
                    }
                });
            });
        });
        ";
        wp_add_inline_script( 'nexura-recaptcha-api', $inline_script );
    }

    /**
     * Renders the hidden field manually if JS fails or as a fallback.
     */
    public function render_field() {
        // Handled dynamically via JS to avoid token expiration
        // We just output an empty div or nothing, the JS will append the input on submit.
    }

    /**
     * Verifies the token via Google API.
     */
    private function verify_token( $token, $action = 'login' ) {
        $secret_key = get_option( 'NEXURA_recaptcha_secret_key', '' );
        if ( empty( $secret_key ) ) {
            return true; // Skip if misconfigured
        }

        // google.com/recaptcha/api/siteverify is called only when the administrator has
        // enabled reCAPTCHA (NEXURA_recaptcha_enabled = '1') — 100% opt-in.
        $response = wp_remote_post( 'https://www.google.com/recaptcha/api/siteverify', [
            'body' => [
                'secret'   => $secret_key,
                'response' => $token,
                'remoteip' => isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : ''
            ]
        ] );

        if ( is_wp_error( $response ) ) {
            return false;
        }

        $body = wp_remote_retrieve_body( $response );
        $result = json_decode( $body, true );

        if ( ! empty( $result['success'] ) && $result['success'] === true ) {
            $threshold = (float) get_option( 'NEXURA_recaptcha_threshold', '0.5' );
            $score = isset( $result['score'] ) ? (float) $result['score'] : 0;
            
            // Log the score
            global $wpdb;
            $table = $wpdb->prefix . 'NEXURA_recaptcha_logs';
            $wpdb->insert( $table, [ // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
                'ip_address' => isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '',
                'action'     => sanitize_text_field( $action ),
                'score'      => $score,
                'timestamp'  => current_time( 'mysql' )
            ] );

            // If test mode is enabled, we never block, just return true
            $test_mode = get_option( 'NEXURA_recaptcha_test_mode', '0' );
            if ( $test_mode === '1' ) {
                return true;
            }

            if ( $score >= $threshold ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Hooked into authenticate.
     */
    public function verify_login( $user, $username, $password ) {
        if ( empty( $username ) || empty( $password ) ) {
            return $user; // Not a login attempt
        }

        if ( $this->is_ip_allowlisted() ) {
            return $user;
        }

        if ( ! isset( $_POST['nexura_recaptcha_token'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
            return new \WP_Error( 'recaptcha_missing', __( '<strong>Error</strong>: reCAPTCHA verification failed. Please try again.', 'nexura-security' ) );
        }

        $token = sanitize_text_field( wp_unslash( $_POST['nexura_recaptcha_token'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
        if ( ! $this->verify_token( $token, 'login' ) ) {
            return new \WP_Error( 'recaptcha_failed', __( '<strong>Error</strong>: reCAPTCHA verification failed (bot detected).', 'nexura-security' ) );
        }

        return $user;
    }

    /**
     * Hooked into registration_errors.
     */
    public function verify_registration( $errors, $sanitized_user_login, $user_email ) {
        if ( $this->is_ip_allowlisted() ) {
            return $errors;
        }

        if ( ! isset( $_POST['nexura_recaptcha_token'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $errors->add( 'recaptcha_missing', __( '<strong>Error</strong>: reCAPTCHA verification failed. Please try again.', 'nexura-security' ) );
            return $errors;
        }

        $token = sanitize_text_field( wp_unslash( $_POST['nexura_recaptcha_token'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
        if ( ! $this->verify_token( $token, 'register' ) ) {
            $errors->add( 'recaptcha_failed', __( '<strong>Error</strong>: reCAPTCHA verification failed (bot detected).', 'nexura-security' ) );
        }

        return $errors;
    }

    /**
     * Checks if the current IP is allowlisted.
     */
    private function is_ip_allowlisted() {
        $allowlist = get_option( 'NEXURA_ip_allowlist', '' );
        if ( empty( $allowlist ) ) {
            return false;
        }

        $ips = explode( "\n", $allowlist );
        $client_ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';

        foreach ( $ips as $ip ) {
            $ip = trim( $ip );
            if ( empty( $ip ) ) continue;

            if ( $ip === $client_ip ) {
                return true;
            }
            
            // Check IP range (e.g. 192.168.1.*)
            if ( strpos( $ip, '*' ) !== false ) {
                $pattern = str_replace( '*', '.*', $ip );
                if ( preg_match( '/^' . $pattern . '$/', $client_ip ) ) {
                    return true;
                }
            }
        }

        return false;
    }
}
