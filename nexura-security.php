<?php

/**
 * Plugin Name: Nexura Security
 * Plugin URI: https://wordpress.org/plugins/nexura-security/
 * Description: Enterprise-level WordPress security plugin with malware scanning, file integrity monitoring, vulnerability auditing, and Google Safe Browsing integration.
 * Version: 1.0.18
 * Author: Nexura Security
 * Author URI: https://profiles.wordpress.org/nexurasecurity/
 * License: GPL-2.0+
 * License URI: http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain: nexura-security
 * Domain Path: /languages
 * 
 */
if ( !defined( 'ABSPATH' ) ) {
    exit;
}
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound, WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound, WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
if ( !function_exists( 'nsp_fs' ) ) {
    // Create a helper function for easy SDK access.
    function nsp_fs() {
        global $nsp_fs;
        if ( !isset( $nsp_fs ) ) {
            // Include Freemius SDK.
            require_once dirname( __FILE__ ) . '/vendor/freemius/start.php';
            $nsp_fs = fs_dynamic_init( array(
                'id'               => '32691',
                'slug'             => 'nexura-security',
                'type'             => 'plugin',
                'public_key'       => 'pk_ffd9b1ec5c329e080bacbdcb26ab0',
                'is_premium'       => false,
                'has_addons'       => false,
                'has_contact'      => false,
                'has_paid_plans'   => true,
                'is_org_compliant' => true,
                'trial'            => array(
                    'days'               => 7,
                    'is_require_payment' => true,
                ),
                'menu'             => array(
                    'slug'    => 'nexura',
                    'support' => false,
                    'contact' => false,
                ),
                'is_live'          => true,
            ) );
        }
        return $nsp_fs;
    }

    // Init Freemius.
    nsp_fs();
    // Signal that SDK was initiated.
    do_action( 'nsp_fs_loaded' );
}
// Ensure backward compatibility: Deactivate old standalone Pro plugin to prevent Fatal Errors
add_action( 'admin_init', function () {
    if ( !function_exists( 'is_plugin_active' ) ) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }
    if ( is_plugin_active( 'nexura-security-pro/nexura-security-pro.php' ) ) {
        deactivate_plugins( 'nexura-security-pro/nexura-security-pro.php' );
        if ( isset( $_GET['activate'] ) ) {
            unset($_GET['activate']);
            // Prevent "plugin activated" notice overriding ours
        }
        add_action( 'admin_notices', function () {
            echo '<div class="notice notice-warning is-dismissible"><p><strong>Nexura Security:</strong> The old standalone <em>Nexura Security Pro</em> plugin has been automatically deactivated. All Pro features are now safely bundled within the main <em>Nexura Security</em> plugin via your active license.</p></div>';
        } );
    }
} );
// phpcs:enable
// Define Constants
if ( !defined( 'NEXURA_VERSION' ) ) {
    define( 'NEXURA_VERSION', '1.0.18' );
}
if ( !defined( 'NEXURA_PLUGIN_DIR' ) ) {
    define( 'NEXURA_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
}
if ( !defined( 'NEXURA_PLUGIN_URL' ) ) {
    define( 'NEXURA_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
}
if ( !defined( 'NEXURA_PLUGIN_BASENAME' ) ) {
    define( 'NEXURA_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );
}
/**
 * Main wrapper class for global utilities.
 */
if ( !class_exists( 'Nexura_Security' ) ) {
    class Nexura_Security {
        /**
         * Centralized capability check for the plugin.
         * Ensures all permission layers use the same capability (preventing bugs).
         *
         * @return bool
         */
        public static function can_manage_security() {
            return current_user_can( 'manage_options' );
        }

    }

}
/**
 * Global helper to securely check if Pro is active.
 * Caches the result to prevent multiple Freemius API calls per request.
 * 
 * @return bool
 */
if ( !function_exists( 'nexura_is_pro' ) ) {
    function nexura_is_pro() {
        static $is_pro = null;
        if ( $is_pro === null ) {
            $is_pro = false;
            // Check if the SDK has premium plan active
            if ( function_exists( 'nsp_fs' ) && nsp_fs()->can_use_premium_code() ) {
                $is_pro = true;
            }
        }
        return $is_pro;
    }

}
// Autoload classes
spl_autoload_register( function ( $class ) {
    $prefix = 'Nexura_Security\\';
    $base_dir = NEXURA_PLUGIN_DIR . 'includes/';
    $len = strlen( $prefix );
    if ( strncmp( $prefix, $class, $len ) !== 0 ) {
        return;
    }
    $relative_class = substr( $class, $len );
    $filename = 'class-' . strtolower( str_replace( '_', '-', $relative_class ) ) . '.php';
    $file = $base_dir . $filename;
    $pro_file = $base_dir . 'pro/' . $filename;
    if ( file_exists( $file ) ) {
        require $file;
        return;
    }
    if ( function_exists( 'nsp_fs' ) ) {
    }
} );
/**
 * Initialize the plugin.
 */
if ( !function_exists( 'Nexura_Security_init' ) ) {
    function Nexura_Security_init() {
        // load_plugin_textdomain is no longer needed per WP.org guidelines (loads automatically)
        $main = new \Nexura_Security\Loader();
        $main->run();
    }

}
add_action( 'plugins_loaded', 'Nexura_Security_init', 0 );
/**
 * Uninstall Hook (Freemius)
 */
nsp_fs()->add_action( 'after_uninstall', 'nexura_fs_uninstall' );
/**
 * License Change Hooks (Freemius)
 * Clears the server-side license verification cache so users get immediate access upon upgrade.
 */
nsp_fs()->add_action( 'after_license_change', function () {
    if ( class_exists( '\\Nexura_Security\\License_Verifier' ) ) {
        \Nexura_Security\License_Verifier::clear_cache();
        \Nexura_Security\License_Verifier::sync_with_remote();
    }
} );
nsp_fs()->add_action( 'after_plan_change', function () {
    if ( class_exists( '\\Nexura_Security\\License_Verifier' ) ) {
        \Nexura_Security\License_Verifier::clear_cache();
    }
} );
if ( !function_exists( 'nexura_fs_uninstall' ) ) {
    function nexura_fs_uninstall() {
        global $wpdb;
        if ( get_option( 'NEXURA_delete_data_on_uninstall', '0' ) === '1' ) {
            // 1. Delete all options
            $wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'NEXURA_%'" );
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            // 2. Drop all custom tables
            $tables = [$wpdb->prefix . 'NEXURA_scan_results', $wpdb->prefix . 'NEXURA_activity_logs', $wpdb->prefix . 'NEXURA_threat_ips'];
            foreach ( $tables as $table ) {
                $wpdb->query( "DROP TABLE IF EXISTS {$table}" );
                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange
            }
        }
        // 3. Clear scheduled hooks
        wp_clear_scheduled_hook( 'NEXURA_scheduled_scan' );
        wp_clear_scheduled_hook( 'NEXURA_daily_fim_check' );
        wp_clear_scheduled_hook( 'NEXURA_daily_gsb_check' );
        wp_clear_scheduled_hook( 'NEXURA_daily_malware_scan' );
        wp_clear_scheduled_hook( 'NEXURA_process_queue' );
        wp_clear_scheduled_hook( 'NEXURA_pro_sync' );
        wp_clear_scheduled_hook( 'NEXURA_sync_threat_intel' );
        // 4. Delete log and quarantine directories
        $upload_dir = wp_upload_dir();
        $log_dir = $upload_dir['basedir'] . '/nexura-logs';
        $quarantine_dir = $upload_dir['basedir'] . '/nexura-quarantine';
        $data_dir = $upload_dir['basedir'] . '/nexura-security';
        $dirs_to_delete = [$log_dir, $quarantine_dir, $data_dir];
        require_once ABSPATH . 'wp-admin/includes/file.php';
        WP_Filesystem();
        global $wp_filesystem;
        foreach ( $dirs_to_delete as $dir ) {
            if ( $wp_filesystem->exists( $dir ) && $wp_filesystem->is_dir( $dir ) ) {
                $wp_filesystem->delete( $dir, true );
                // true for recursive deletion
            }
        }
        // 5. Remove WAF drop-in if exists
        $dropin_dest = ABSPATH . 'nexura-waf.php';
        if ( $wp_filesystem->exists( $dropin_dest ) ) {
            $content = $wp_filesystem->get_contents( $dropin_dest );
            if ( strpos( $content, 'Nexura Security' ) !== false ) {
                $wp_filesystem->delete( $dropin_dest );
            }
        }
    }

}
/**
 * Activation Hook
 */
register_activation_hook( __FILE__, function () {
    if ( file_exists( NEXURA_PLUGIN_DIR . 'includes/class-activator.php' ) ) {
        require_once NEXURA_PLUGIN_DIR . 'includes/class-activator.php';
        \Nexura_Security\Activator::activate();
    }
} );
/**
 * Deactivation Hook
 */
register_deactivation_hook( __FILE__, function () {
    if ( file_exists( NEXURA_PLUGIN_DIR . 'includes/class-deactivator.php' ) ) {
        require_once NEXURA_PLUGIN_DIR . 'includes/class-deactivator.php';
        \Nexura_Security\Deactivator::deactivate();
    }
} );
/**
 * Global Pro Feature Helpers
 * Used in Pro tease pages and views to blur content and show a locked modal.
 */
if ( !function_exists( 'nexura_pro_get_blur_style' ) ) {
    function nexura_pro_get_blur_style() {
        if ( function_exists( 'nexura_is_pro' ) && nexura_is_pro() ) {
            return '';
        }
        if ( class_exists( '\\Nexura_Security\\License_Verifier' ) && \Nexura_Security\License_Verifier::is_verified() ) {
            return '';
        }
        return 'opacity: 0.5; pointer-events: none; user-select: none;';
    }

}
if ( !function_exists( 'nexura_pro_render_locked_modal' ) ) {
    function nexura_pro_render_locked_modal() {
        if ( function_exists( 'nexura_is_pro' ) && nexura_is_pro() ) {
            return;
        }
        if ( class_exists( '\\Nexura_Security\\License_Verifier' ) && \Nexura_Security\License_Verifier::is_verified() ) {
            return;
        }
        echo '<div id="nexura-pro-upgrade-modal" style="position: absolute; top: 20%; left: 50%; transform: translate(-50%, 0); z-index: 99999; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); text-align: center; pointer-events: auto; border: 1px solid #e2e8f0; min-width: 300px;">
            <div style="font-size: 20px; font-weight: 600; margin-bottom: 10px; color: #1e293b;">Pro Feature Locked</div>
            <div style="margin-bottom: 20px; color: #64748b; font-size: 14px;">Upgrade to Nexura Security Pro to unlock this feature.</div>
            <a href="' . esc_url( admin_url( 'admin.php?page=nexura-pricing' ) ) . '" class="button button-primary" style="background: #ec4899; border-color: #ec4899; padding: 5px 20px;">Upgrade Now</a>
        </div>';
    }

}