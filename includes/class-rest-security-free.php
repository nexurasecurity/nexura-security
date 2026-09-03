<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class REST_Security_Free
 *
 * Hardens the WordPress REST API and XML-RPC in the free version.
 */
class REST_Security_Free {

    public function init() {
        $disable_user_enum = get_option( 'NEXURA_disable_user_enum', '1' );
        $disable_xmlrpc = get_option( 'NEXURA_disable_xmlrpc', '0' );
        $disable_app_pass = get_option( 'NEXURA_disable_app_passwords', '0' );

        // Block user enumeration via REST API
        if ( $disable_user_enum === '1' ) {
            add_filter( 'rest_endpoints', [ $this, 'block_user_enumeration' ] );
            add_action( 'template_redirect', [ $this, 'block_author_enumeration' ], 1 );
        }

        // Disable XML-RPC (common attack vector)
        if ( $disable_xmlrpc === '1' ) {
            add_filter( 'xmlrpc_enabled', '__return_false', 9999 );
            add_filter( 'xmlrpc_methods', '__return_empty_array', 9999 );
            add_filter( 'wp_headers', [ $this, 'remove_xmlrpc_header' ] );
        }
        
        // Disable Application Passwords
        if ( $disable_app_pass === '1' ) {
            add_filter( 'wp_is_application_passwords_available', '__return_false' );
        }
    }

    /**
     * Block user enumeration via REST API.
     * Removes /wp/v2/users and /wp/v2/users/{id} endpoints.
     */
    public function block_user_enumeration( $endpoints ) {
        if ( current_user_can( 'list_users' ) ) {
            return $endpoints;
        }

        $blocked = [
            '/wp/v2/users',
            '/wp/v2/users/(?P<id>[\d]+)',
            '/wp/v2/users/me',
        ];

        foreach ( $blocked as $route ) {
            if ( isset( $endpoints[ $route ] ) ) {
                unset( $endpoints[ $route ] );
            }
        }

        return $endpoints;
    }

    /**
     * Block user enumeration via ?author=N query parameter.
     */
    public function block_author_enumeration() {
        if ( ! is_admin() && isset( $_GET['author'] ) && ! current_user_can( 'list_users' ) ) {
            wp_die(
                esc_html__( 'Author enumeration is disabled for security reasons.', 'nexura-security' ),
                esc_html__( '403 — Forbidden', 'nexura-security' ),
                [ 'response' => 403 ]
            );
        }
    }

    /**
     * Remove X-Pingback header (XML-RPC related).
     */
    public function remove_xmlrpc_header( $headers ) {
        unset( $headers['X-Pingback'] );
        return $headers;
    }
}
