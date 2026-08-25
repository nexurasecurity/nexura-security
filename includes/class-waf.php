<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WAF
 * 
 * Web Application Firewall to block SQLi, XSS, RCE, LFI/RFI, and Traversal.
 */
class WAF {

    public function init() {
        // Run firewall on very early hook
        add_action( 'plugins_loaded', [ $this, 'run_firewall' ], 1 );
        
        // Block bad bots
        add_action( 'plugins_loaded', [ $this, 'block_bad_bots' ], 2 );

        // Protect REST API
        add_filter( 'rest_authentication_errors', [ $this, 'secure_rest_api' ] );
    }

    public function run_firewall() {
        // Only run if the firewall is enabled in settings (default true)
        if ( ! get_option( 'NEXURA_enable_waf', 1 ) ) {
            return;
        }

        // Whitelist admin backend for logged in admins to prevent false positives during content editing
        if ( is_admin() && current_user_can( 'manage_options' ) ) {
            return;
        }

        $payloads = [
            'sqli' => [
                '/union\s+all\s+select/i',
                '/information_schema/i',
                '/concat\s*\(/i',
                '/waitfor\s+delay/i',
                '/select\s+.*\s+from/i'
            ],
            'xss' => [
                '/<script.*?>/i',
                '/javascript:/i',
                '/onerror\s*=/i',
                '/onload\s*=/i',
                '/e'.'val\s*\(/i'
            ],
            'lfi_rfi_traversal' => [
                '/\.\.\//',
                '/etc\/passwd/i',
                '/wp-config\.php/i',
                '/(?:http|https|ftp):\/\//i'
            ],
            'rce' => [
                '/sys'.'tem\s*\(/i',
                '/shell_'.'exec\s*\(/i',
                '/base64_'.'decode\s*\(/i',
                '/pass'.'thru\s*\(/i'
            ]
        ];

        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended
        $request_data = array_merge( $_GET, $_POST, $_COOKIE );
        $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? urldecode( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

        foreach ( $payloads as $type => $patterns ) {
            foreach ( $patterns as $pattern ) {
                if ( preg_match( $pattern, $request_uri ) ) {
                    $this->trigger_block( $type );
                }
                foreach ( $request_data as $key => $value ) {
                    if ( is_string( $value ) && preg_match( $pattern, $value ) ) {
                        $this->trigger_block( $type );
                    }
                }
            }
        }
    }

    public function block_bad_bots() {
        if ( ! get_option( 'NEXURA_enable_bot_protection', 1 ) ) {
            return;
        }

        $user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
        if ( empty( $user_agent ) ) {
            // Block empty user agents (often scripts/bots)
            $this->trigger_block( 'empty_user_agent' );
        }

        $bad_bots = [
            'AhrefsBot', 'SemrushBot', 'MJ12bot', 'DotBot', 'PetalBot', 'Baiduspider',
            'curl', 'python-requests', 'wget', 'libwww-perl', 'nmap', 'sqlmap', 'zmeu'
        ];

        foreach ( $bad_bots as $bot ) {
            if ( stripos( $user_agent, $bot ) !== false ) {
                $this->trigger_block( 'bad_bot' );
            }
        }
    }

    public function secure_rest_api( $result ) {
        // If a previous authentication check has failed, bail.
        if ( ! empty( $result ) ) {
            return $result;
        }

        // Restrict REST API to logged in users only (unless explicitly allowed via filters)
        if ( get_option( 'NEXURA_secure_rest_api', 1 ) ) {
            if ( ! is_user_logged_in() ) {
                // Allow specific endpoints that need public access (like Contact Form 7)
                $whitelist = apply_filters( 'nexura_rest_api_whitelist', [
                    '/wp/v2/users/me', // Handled by core auth
                    '/contact-form-7/v1'
                ] );

                $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
                foreach ( $whitelist as $endpoint ) {
                    if ( strpos( $request_uri, $endpoint ) !== false ) {
                        return $result;
                    }
                }

                return new \WP_Error( 'rest_forbidden', __( 'REST API access restricted to authenticated users by Nexura Security.', 'nexura-security' ), [ 'status' => rest_authorization_required_code() ] );
            }
        }

        return $result;
    }

    private function trigger_block( $reason ) {
        $ip = '127.0.0.1';
        if ( isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
            $ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
        } elseif ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
            $ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
        }

        if ( class_exists( '\Nexura_Security\Attack_Logger' ) ) {
            \Nexura_Security\Attack_Logger::log_attack( $ip, 'WAF Block: ' . $reason, 'Blocked' );
        }

        header('HTTP/1.1 403 Forbidden');
        wp_die( '<h1>Access Denied</h1><p>Your request was blocked by the Nexura Web Application Firewall.</p>', 'Security Block', [ 'response' => 403 ] );
    }
}
