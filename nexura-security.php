<?php
/**
 * Plugin Name: Nexura Security
 * Plugin URI: https://wordpress.org/plugins/nexura-security/
 * Description: Enterprise-level WordPress security plugin with malware scanning, file integrity monitoring, vulnerability auditing, and Google Safe Browsing integration.
 * Version: 1.0.11
 * Author: Nexura Security
 * Author URI: https://profiles.wordpress.org/nexurasecurity/
 * License: GPL-2.0+
 * License URI: http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain: nexura-security
 * Domain Path: /languages
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound, WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound, WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
if ( ! function_exists( 'nexurasec_fs' ) ) {
    // Create a helper function for easy SDK access.
    function nexurasec_fs() {
        global $nexurasec_fs;

        if ( ! isset( $nexurasec_fs ) ) {
            // Include Freemius SDK.
            require_once dirname( __FILE__ ) . '/vendor/freemius/start.php';

            $nexurasec_fs = fs_dynamic_init( array(
                'id'                  => '32691',
                'slug'                => 'nexura-security',
                'premium_slug'        => 'nexura-security-pro',
                'type'                => 'plugin',
                'public_key'          => 'pk_ffd9b1ec5c329e080bacbdcb26ab0',
                'is_premium'          => false,
                'has_addons'          => false,
                'has_paid_plans'      => true,
                'is_org_compliant'    => true,
                'menu'                => array(
                    'slug'           => 'nexura',
                    'support'        => true,
                    'contact'        => true,
                    'position'       => 3,
                ),
            ) );
        }

        return $nexurasec_fs;
    }

    // Init Freemius.
    nexurasec_fs();
    // Signal that SDK was initiated.
    do_action( 'nexurasec_fs_loaded' );
}
// phpcs:enable

// Define Constants
if ( ! defined( 'NEXURA_VERSION' ) ) {
    define( 'NEXURA_VERSION', '1.0.11' );
}
define( 'NEXURA_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'NEXURA_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'NEXURA_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );

// Gracefully remove Freemius "Activate Premium version" notice if Pro is already active
add_action( 'admin_init', function() {
    if ( defined( 'NEXURA_PRO_VERSION' ) && function_exists( 'nexurasec_fs' ) ) {
        try {
            $fs = nexurasec_fs();
            $reflection = new ReflectionClass( $fs );
            if ( $reflection->hasProperty( '_admin_notices' ) ) {
                $property = $reflection->getProperty( '_admin_notices' );
                $property->setAccessible( true );
                $admin_notices = $property->getValue( $fs );
                
                if ( $admin_notices && method_exists( $admin_notices, 'remove_sticky' ) ) {
                    $admin_notices->remove_sticky( array( 'activate_premium_version', 'plan_upgraded' ) );
                }
            }
        } catch ( Exception $e ) {
            // Silently fail if reflection is restricted
        }
    }
}, 20 );

// Intercept the subscription plan check and sync it with Freemius License status
add_filter( 'pre_option_NEXURA_subscription_plan', function( $value ) {
    return nexura_is_pro() ? 'pro' : 'free';
} );

/**
 * Global helper to securely check if Pro is active.
 * Caches the result to prevent multiple Freemius API calls per request.
 * 
 * @return bool
 */
function nexura_is_pro() {
    static $is_pro = null;
    if ( $is_pro === null ) {
        $is_pro_active = false;
        
        // Check if Free plugin has premium plan active
        if ( function_exists('nexurasec_fs') && nexurasec_fs()->can_use_premium_code() ) {
            $is_pro_active = true;
        }
        
        // Check if Pro plugin (Add-on) is installed and its license is active
        if ( function_exists('nsp_fs') && nsp_fs()->can_use_premium_code() ) {
            $is_pro_active = true;
        }

        // Only return true if:
        // 1. Pro plugin constant is defined (Pro is physically active)
        // 2. Either Free or Pro plugin has a valid premium license
        // 3. Pro plugin core file exists (not a stub)
        $is_pro = (
            defined('NEXURA_PRO_VERSION') &&
            $is_pro_active &&
            file_exists( WP_PLUGIN_DIR . '/nexura-security-pro/includes/class-pro-file-manager.php' )
        );
    }
    return $is_pro;
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
	$file = $base_dir . 'class-' . strtolower( str_replace( '_', '-', $relative_class ) ) . '.php';

	if ( file_exists( $file ) ) {
		require $file;
	}
} );

/**
 * Initialize the plugin.
 */
function Nexura_Security_init() {
    // load_plugin_textdomain is no longer needed per WP.org guidelines (loads automatically)
	$main = new \Nexura_Security\Loader();
	$main->run();
}
add_action( 'plugins_loaded', 'Nexura_Security_init' );

/**
 * Uninstall Hook (Freemius)
 */
nexurasec_fs()->add_action( 'after_uninstall', 'nexurasec_fs_uninstall' );
function nexurasec_fs_uninstall() {
    global $wpdb;

    if ( get_option( 'NEXURA_delete_data_on_uninstall', '0' ) === '1' ) {
        // 1. Delete all options
        $wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'NEXURA_%'" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        
        // 2. Drop all custom tables
        $tables = [
            $wpdb->prefix . 'NEXURA_scan_results',
            $wpdb->prefix . 'NEXURA_activity_logs',
            $wpdb->prefix . 'NEXURA_threat_ips',
        ];
        
        foreach ( $tables as $table ) {
            $wpdb->query( "DROP TABLE IF EXISTS {$table}" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange
        }
    }

    // 3. Clear scheduled hooks
    wp_clear_scheduled_hook( 'NEXURA_scheduled_scan' );
    wp_clear_scheduled_hook( 'NEXURA_daily_fim_check' );
    wp_clear_scheduled_hook( 'NEXURA_daily_gsb_check' );
    wp_clear_scheduled_hook( 'NEXURA_daily_malware_scan' );
    wp_clear_scheduled_hook( 'NEXURA_process_queue' );
    wp_clear_scheduled_hook( 'NEXURA_sync_threat_intel' );

    // 4. Delete log and quarantine directories
    $upload_dir = wp_upload_dir();
    $log_dir = $upload_dir['basedir'] . '/nexura-logs';
    $quarantine_dir = $upload_dir['basedir'] . '/nexura-quarantine';
    $data_dir = $upload_dir['basedir'] . '/nexura-security';

    $dirs_to_delete = [ $log_dir, $quarantine_dir, $data_dir ];

    require_once ABSPATH . 'wp-admin/includes/file.php';
    WP_Filesystem();
    global $wp_filesystem;

    foreach ( $dirs_to_delete as $dir ) {
        if ( $wp_filesystem->exists( $dir ) && $wp_filesystem->is_dir( $dir ) ) {
            $wp_filesystem->delete( $dir, true ); // true for recursive deletion
        }
    }

    // 5. Remove Auto-Heal Drop-in if it belongs to Nexura
    $dropin_dest = WP_CONTENT_DIR . '/fatal-error-handler.php';
    if ( $wp_filesystem->exists( $dropin_dest ) ) {
        $content = $wp_filesystem->get_contents( $dropin_dest );
        if ( strpos( $content, 'Nexura Security' ) !== false ) {
            $wp_filesystem->delete( $dropin_dest );
        }
    }
}

/**
 * Activation Hook
 */
register_activation_hook( __FILE__, function() {
    if ( file_exists( NEXURA_PLUGIN_DIR . 'includes/class-activator.php' ) ) {
        require_once NEXURA_PLUGIN_DIR . 'includes/class-activator.php';
        \Nexura_Security\Activator::activate();
    }
} );

/**
 * Deactivation Hook
 */
register_deactivation_hook( __FILE__, function() {
    if ( file_exists( NEXURA_PLUGIN_DIR . 'includes/class-deactivator.php' ) ) {
        require_once NEXURA_PLUGIN_DIR . 'includes/class-deactivator.php';
        \Nexura_Security\Deactivator::deactivate();
    }
} );

