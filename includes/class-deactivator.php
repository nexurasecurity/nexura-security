<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Deactivator
 * 
 * Fired during plugin deactivation.
 */
class Deactivator {

    /**
     * Deactivation logic.
     */
    public static function deactivate() {
        // Clear scheduled crons
        wp_clear_scheduled_hook( 'NEXURA_daily_scan' );
        
        // Clear license data to force re-authentication upon reactivation
        delete_option( 'NEXURA_license_key' );
        delete_option( 'NEXURA_subscription_plan' );
        delete_option( 'NEXURA_registered_email' );

        // Remove Auto-Heal Drop-in if it belongs to Nexura
        $dropin_dest = WP_CONTENT_DIR . '/fatal-error-handler.php';
        if ( file_exists( $dropin_dest ) ) {
            $content = file_get_contents( $dropin_dest );
            if ( strpos( $content, 'Nexura Security' ) !== false ) {
                @wp_delete_file( $dropin_dest );
            }
        }

        // Remove WAF and Hardening rules from .htaccess
        require_once ABSPATH . 'wp-admin/includes/file.php';
        require_once ABSPATH . 'wp-admin/includes/misc.php';
        $htaccess_file = get_home_path() . '.htaccess';
        if ( file_exists( $htaccess_file ) ) {
            // Ensure writable if locked
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
            @chmod( $htaccess_file, 0644 );
            insert_with_markers( $htaccess_file, 'Nexura Security', [] );
        }

        // Remove WAF rules from .user.ini
        $user_ini_file = get_home_path() . '.user.ini';
        if ( file_exists( $user_ini_file ) ) {
            $current_ini = @file_get_contents( $user_ini_file );
            $pattern = '/; BEGIN Nexura Security.*?; END Nexura Security\n?/s';
            $current_ini = preg_replace( $pattern, '', $current_ini );
            
            if ( ! empty( trim( $current_ini ) ) ) {
                @file_put_contents( $user_ini_file, trim( $current_ini ) . "\n" );
            } else {
                @wp_delete_file( $user_ini_file );
            }
        }
        
        // Delete Login Security data if setting is enabled
        if ( get_option( 'NEXURA_delete_data_on_deactivation', '0' ) === '1' ) {
            global $wpdb;
            
            // Delete user meta related to 2FA
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->query( "DELETE FROM {$wpdb->usermeta} WHERE meta_key IN (
                'NEXURA_2fa_enabled',
                'NEXURA_2fa_secret',
                'NEXURA_2fa_recovery_codes',
                'NEXURA_2fa_remember_hashes',
                'NEXURA_last_login',
                'NEXURA_2fa_grace_period_start'
            )" );
            
            // Delete Login Security options
            $options = [
                'NEXURA_2fa_roles',
                'NEXURA_2fa_grace_period',
                'NEXURA_disable_xmlrpc',
                'NEXURA_require_xmlrpc_2fa',
                'NEXURA_recaptcha_enabled',
                'NEXURA_recaptcha_site_key',
                'NEXURA_recaptcha_secret_key',
                'NEXURA_recaptcha_threshold',
                'NEXURA_recaptcha_test_mode',
                'NEXURA_ip_allowlist',
                'NEXURA_allow_remember_device',
                'NEXURA_wc_integration',
                'NEXURA_wc_account_menu',
                'NEXURA_2fa_shortcode',
                'NEXURA_wc_single_column',
                'NEXURA_ntp_sync',
                'NEXURA_show_last_login',
                'NEXURA_delete_data_on_deactivation',
            ];
            foreach ( $options as $option ) {
                delete_option( $option );
            }
        }
    }
}
