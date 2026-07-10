<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Session_Manager
 * 
 * Handles advanced session management including Idle Timeout.
 */
class Session_Manager {

    public function init() {
        if ( ! get_option( 'NEXURA_enable_idle_timeout', 1 ) ) {
            return;
        }

        // Enqueue scripts for tracking idle time
        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_scripts' ] );
        add_action( 'wp_enqueue_scripts', [ $this, 'enqueue_scripts' ] );

        // Ajax endpoint to log out idle users
        add_action( 'wp_ajax_NEXURA_idle_logout', [ $this, 'ajax_idle_logout' ] );
    }

    public function enqueue_scripts() {
        if ( ! is_user_logged_in() ) {
            return;
        }

        $timeout_minutes = (int) get_option( 'NEXURA_idle_timeout_minutes', 15 );
        if ( $timeout_minutes <= 0 ) {
            return; // Disabled
        }

        wp_enqueue_script( 'nexura-session-manager', NEXURA_PLUGIN_URL . 'admin/js/session-manager.js', [ 'jquery' ], NEXURA_VERSION, true );
        wp_localize_script( 'nexura-session-manager', 'NEXURA_session', [
            'ajax_url' => admin_url( 'admin-ajax.php' ),
            'timeout_ms' => $timeout_minutes * 60 * 1000,
            'nonce' => wp_create_nonce( 'NEXURA_session_nonce' ),
            'warning_msg' => esc_html__( 'You have been inactive for a while. You will be logged out in 1 minute.', 'nexura-security' )
        ] );
    }

    public function ajax_idle_logout() {
        check_ajax_referer( 'NEXURA_session_nonce', 'nonce' );
        
        wp_logout();
        
        wp_send_json_success( [
            'redirect' => wp_login_url( home_url() . '?logged_out=idle' )
        ] );
    }
}
