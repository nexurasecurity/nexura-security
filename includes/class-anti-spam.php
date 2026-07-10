<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Anti_Spam
 * 
 * Protects WordPress comment forms, checkout forms, and login/register forms from bot submissions.
 */
class Anti_Spam {

    /**
     * Initializes anti-spam and verification hooks.
     */
    public function init() {
        // Hard block XML-RPC requests (highly targeted by botnets) if option is enabled
        if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST && get_option( 'NEXURA_htaccess_xmlrpc', 0 ) ) {
            wp_die( 'XML-RPC is disabled on this site.', 'Access Denied', [ 'response' => 403 ] );
        }

        // Comment form protection
        if ( get_option( 'NEXURA_enable_comment_spam_protection', 1 ) ) {
            add_filter( 'comment_form_submit_field', [ $this, 'add_captcha_to_comment_form' ], 10, 2 );
            add_filter( 'pre_comment_on_post', [ $this, 'verify_comment_captcha' ] );
            add_action( 'wp_enqueue_scripts', [ $this, 'enqueue_scripts' ] );
        }

        // WooCommerce Checkout Integration
        if ( class_exists( 'WooCommerce' ) && get_option( 'NEXURA_enable_woo_protection', 1 ) ) {
            add_action( 'woocommerce_review_order_before_submit', [ $this, 'add_captcha_to_woo_checkout' ] );
            add_action( 'woocommerce_checkout_process', [ $this, 'verify_woo_checkout_captcha' ] );
            add_action( 'wp_enqueue_scripts', [ $this, 'enqueue_scripts' ] );
        }

        // WordPress Login, Registration, and Password Recovery Protection
        $site_key = get_option( 'NEXURA_captcha_site_key', '' );
        if ( ! empty( $site_key ) ) {
            add_action( 'login_form', [ $this, 'add_captcha_to_login_form' ] );
            add_action( 'register_form', [ $this, 'add_captcha_to_login_form' ] );
            add_action( 'lostpassword_form', [ $this, 'add_captcha_to_login_form' ] );
            add_action( 'login_enqueue_scripts', [ $this, 'enqueue_login_scripts' ] );

            add_filter( 'wp_authenticate_user', [ $this, 'verify_login_captcha' ], 20, 2 );
            add_filter( 'registration_errors', [ $this, 'verify_registration_captcha' ], 10, 3 );
            add_action( 'lostpassword_post', [ $this, 'verify_lostpassword_captcha' ] );
        }
    }

    /**
     * Enqueue Turnstile/reCAPTCHA scripts on front-end pages.
     */
    public function enqueue_scripts() {
        if ( ( is_singular() && comments_open() ) || ( function_exists('is_checkout') && is_checkout() ) ) {
            $this->enqueue_captcha_library();
        }
    }

    /**
     * Enqueue Turnstile/reCAPTCHA scripts on the login page.
     */
    public function enqueue_login_scripts() {
        $this->enqueue_captcha_library();
    }

    /**
     * Helper to load the appropriate CAPTCHA JavaScript library.
     */
    private function enqueue_captcha_library() {
        $site_key = get_option( 'NEXURA_captcha_site_key', '' );
        if ( empty( $site_key ) ) {
            return;
        }

        $type = get_option( 'NEXURA_captcha_type', 'turnstile' );
        if ( $type === 'turnstile' ) {
            wp_enqueue_script( 'nexura-turnstile', 'https://challenges.cloudflare.com/turnstile/v0/api.js', [], NEXURA_VERSION, true ); // phpcs:ignore PluginCheck.CodeAnalysis.EnqueuedResourceOffloading.OffloadedContent
        } elseif ( $type === 'recaptcha' ) {
            // google.com/recaptcha is only loaded when the administrator has explicitly
            // configured reCAPTCHA as the CAPTCHA provider — 100% opt-in.
            wp_enqueue_script( 'nexura-recaptcha', 'https://www.google.com/recaptcha/api.js', [], NEXURA_VERSION, true ); // phpcs:ignore PluginCheck.CodeAnalysis.EnqueuedResourceOffloading.OffloadedContent
        }
    }

    /**
     * Appends Turnstile/reCAPTCHA block to the comment form submit field.
     */
    public function add_captcha_to_comment_form( $submit_field, $args ) {
        if ( is_user_logged_in() ) {
            return $submit_field;
        }

        $site_key = get_option( 'NEXURA_captcha_site_key', '' );
        if ( empty( $site_key ) ) {
            return $submit_field;
        }

        $type = get_option( 'NEXURA_captcha_type', 'turnstile' );
        $captcha_html = '<div style="margin-bottom: 15px;">';
        
        if ( $type === 'turnstile' ) {
            $captcha_html .= '<div class="cf-turnstile" data-sitekey="' . esc_attr( $site_key ) . '"></div>';
        } elseif ( $type === 'recaptcha' ) {
            $captcha_html .= '<div class="g-recaptcha" data-sitekey="' . esc_attr( $site_key ) . '"></div>';
        }
        
        $captcha_html .= '</div>';

        return $captcha_html . $submit_field;
    }

    /**
     * Appends Turnstile/reCAPTCHA to the login, register, and lost password forms.
     */
    public function add_captcha_to_login_form() {
        $site_key = get_option( 'NEXURA_captcha_site_key', '' );
        if ( empty( $site_key ) ) {
            return;
        }

        $type = get_option( 'NEXURA_captcha_type', 'turnstile' );
        echo '<div style="margin-bottom: 15px; display: flex; justify-content: center;">';
        if ( $type === 'turnstile' ) {
            echo '<div class="cf-turnstile" data-sitekey="' . esc_attr( $site_key ) . '"></div>';
        } elseif ( $type === 'recaptcha' ) {
            echo '<div class="g-recaptcha" data-sitekey="' . esc_attr( $site_key ) . '"></div>';
        }
        echo '</div>';
    }

    /**
     * Shared helper to verify Turnstile/reCAPTCHA token.
     *
     * @return bool True if valid or not configured, false otherwise.
     */
    private function verify_captcha_token() {
        $site_key = get_option( 'NEXURA_captcha_site_key', '' );
        $secret = get_option( 'NEXURA_captcha_secret_key', '' );

        if ( empty( $site_key ) || empty( $secret ) ) {
            return true; // Pass if key setup is incomplete
        }

        $type = get_option( 'NEXURA_captcha_type', 'turnstile' );
        $is_valid = false;

        if ( $type === 'turnstile' && isset( $_POST['cf-turnstile-response'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $response = wp_remote_post( 'https://challenges.cloudflare.com/turnstile/v0/siteverify', [
                'body' => [
                    'secret'   => $secret,
                    'response' => sanitize_text_field( wp_unslash( $_POST['cf-turnstile-response'] ) ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
                    'remoteip' => isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : ''
                ]
            ] );
            if ( ! is_wp_error( $response ) ) {
                $body = json_decode( wp_remote_retrieve_body( $response ), true );
                $is_valid = ! empty( $body['success'] );
            }
        } elseif ( $type === 'recaptcha' && isset( $_POST['g-recaptcha-response'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
            // google.com/recaptcha/api/siteverify is called only when reCAPTCHA is the
            // administrator-chosen CAPTCHA provider. This is a fully opt-in external service.
            $response = wp_remote_post( 'https://www.google.com/recaptcha/api/siteverify', [
                'body' => [
                    'secret'   => $secret,
                    'response' => sanitize_text_field( wp_unslash( $_POST['g-recaptcha-response'] ) ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
                    'remoteip' => isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : ''
                ]
            ] );
            if ( ! is_wp_error( $response ) ) {
                $body = json_decode( wp_remote_retrieve_body( $response ), true );
                $is_valid = ! empty( $body['success'] );
            }
        }

        return $is_valid;
    }

    /**
     * Verifies CAPTCHA on the comment form.
     */
    public function verify_comment_captcha( $comment_post_id ) {
        if ( is_user_logged_in() ) {
            return;
        }

        if ( ! $this->verify_captcha_token() ) {
            wp_die( 
                '<strong>Nexura Security:</strong> Error verifying CAPTCHA. Please prove you are human and try again.',
                'Security Check Failed',
                [ 'response' => 403, 'back_link' => true ]
            );
        }
    }

    /**
     * Verifies CAPTCHA during WooCommerce checkout.
     */
    public function verify_woo_checkout_captcha() {
        if ( ! $this->verify_captcha_token() ) {
            wc_add_notice( __( 'Security check failed. Please verify that you are human.', 'nexura-security' ), 'error' );
        }
    }

    /**
     * Verifies CAPTCHA on standard login form.
     */
    public function verify_login_captcha( $user, $password ) {
        if ( defined( 'XMLRPC_REQUEST' ) || defined( 'DOING_AJAX' ) || defined( 'DOING_CRON' ) ) {
            return $user;
        }

        if ( is_wp_error( $user ) ) {
            return $user;
        }

        if ( ! $this->verify_captcha_token() ) {
            return new \WP_Error( 'captcha_failed', '<strong>Nexura Security:</strong> Human verification failed. Please check the CAPTCHA checkbox.' );
        }

        return $user;
    }

    /**
     * Verifies CAPTCHA on registration errors check.
     */
    public function verify_registration_captcha( $errors, $sanitized_user_login, $user_email ) {
        if ( ! $this->verify_captcha_token() ) {
            $errors->add( 'captcha_failed', '<strong>Nexura Security:</strong> Human verification failed. Please try again.' );
        }
        return $errors;
    }

    /**
     * Verifies CAPTCHA on lost password form submit.
     */
    public function verify_lostpassword_captcha() {
        if ( ! $this->verify_captcha_token() ) {
            wp_die(
                '<strong>Nexura Security:</strong> Human verification failed. Please go back and try again.',
                'Security Check Failed',
                [ 'response' => 403, 'back_link' => true ]
            );
        }
    }

    /**
     * Renders Turnstile/reCAPTCHA for WooCommerce Checkout.
     */
    public function add_captcha_to_woo_checkout() {
        $site_key = get_option( 'NEXURA_captcha_site_key', '' );
        if ( empty( $site_key ) ) return;

        $type = get_option( 'NEXURA_captcha_type', 'turnstile' );
        echo '<div class="nexura-woo-captcha" style="margin: 20px 0; display:flex; justify-content:center;">';
        if ( $type === 'turnstile' ) {
            echo '<div class="cf-turnstile" data-sitekey="' . esc_attr( $site_key ) . '"></div>';
        } elseif ( $type === 'recaptcha' ) {
            echo '<div class="g-recaptcha" data-sitekey="' . esc_attr( $site_key ) . '"></div>';
        }
        echo '</div>';
    }
}
