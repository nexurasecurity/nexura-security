<?php
/**
 * Plugin Name: Nexura Security
 * Plugin URI: https://wordpress.org/plugins/nexura-security/
 * Description: Enterprise-level WordPress security plugin with malware scanning, file integrity monitoring, vulnerability auditing, and Google Safe Browsing integration.
 * Version: 1.0.6
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
            require_once dirname( __FILE__ ) . '/freemius/start.php';

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
                    'support'        => false,
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
define( 'NEXURA_VERSION', '1.0.6' );
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
        // Only return true if:
        // 1. Pro plugin constant is defined (Pro is physically active)
        // 2. Freemius SDK is loaded
        // 3. Freemius license is valid
        // 4. Pro plugin core file exists (not a stub)
        $is_pro = (
            defined('NEXURA_PRO_VERSION') &&
            function_exists('nexurasec_fs') &&
            nexurasec_fs()->can_use_premium_code() &&
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
        $wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'NEXURA_%'" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        
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


// BULLETPROOF PRO AUTOLOADER (Safeguard against manual Pro plugin reverts)
add_action('plugins_loaded', function() {
    spl_autoload_register(function ($class) {
        if (strpos($class, 'Nexura_Security\\') === 0 || $class === 'Nexura_Cloudflare_Manager' || $class === 'Nexura_Virtual_Patcher') {
            $map = [
                'Nexura_Security\AI_Assistant_Settings' => 'NexuraSys\Ai\AI_Assistant_Settings',
                'Nexura_Security\AI_Auto_Fixer' => 'NexuraSys\Ai\AI_Auto_Fixer',
                'Nexura_Security\AI_Engine' => 'NexuraSys\Ai\AI_Engine',
                'Nexura_Security\Advanced_Scanner' => 'NexuraSys\Scanner\Advanced_Scanner',
                'Nexura_Security\Pro_Scanner' => 'NexuraSys\Scanner\Pro_Scanner',
                'Nexura_Security\Advanced_Malware_Detection' => 'NexuraSys\Scanner\Advanced_Malware_Detection',
                'Nexura_Security\Scan_Session' => 'NexuraSys\Scanner\Scan_Session',
                'Nexura_Security\Asset_Scanner' => 'NexuraSys\Scanner\Asset_Scanner',
                'Nexura_Security\Pro_FIM' => 'NexuraSys\Scanner\Pro_FIM',
                'Nexura_Security\Core_Restorer' => 'NexuraSys\Scanner\Core_Restorer',
                'Nexura_Security\Snapshot_Manager' => 'NexuraSys\Scanner\Snapshot_Manager',
                'Nexura_Security\Quarantine' => 'NexuraSys\Scanner\Quarantine',
                'Nexura_Security\Learning_DB' => 'NexuraSys\Scanner\Learning_DB',
                'Nexura_Security\Pro\Learning_Manager' => 'NexuraSys\Scanner\Learning_Manager',
                'Nexura_Security\Entropy_Analyzer' => 'NexuraSys\Scanner\Entropy_Analyzer',
                'Nexura_Security\Allowlist_Engine' => 'NexuraSys\Scanner\Allowlist_Engine',
                'Nexura_Security\Confidence_Engine' => 'NexuraSys\Scanner\Confidence_Engine',
                'Nexura_Security\WAF_Dashboard' => 'NexuraSys\Firewall\WAF_Dashboard',
                'Nexura_Security\Edge_Firewall_Settings' => 'NexuraSys\Firewall\Edge_Firewall_Settings',
                'Nexura_Cloudflare_Manager' => 'NexuraSys\Firewall\Cloudflare_Manager',
                'Nexura_Security\Server_Rule_Manager' => 'NexuraSys\Firewall\Server_Rule_Manager',
                'Nexura_Security\Threat_Intel_Feed' => 'NexuraSys\Firewall\Threat_Intel_Feed',
                'Nexura_Security\Database_IDS' => 'NexuraSys\Firewall\Database_IDS',
                'Nexura_Security\ACME_Client' => 'NexuraSys\Firewall\ACME_Client',
                'Nexura_Security\SSL_Manager' => 'NexuraSys\Firewall\SSL_Manager',
                'Nexura_Virtual_Patcher' => 'NexuraSys\Firewall\Virtual_Patcher',
                'Nexura_Security\DB_Optimizer' => 'NexuraSys\Optimization\DB_Optimizer',
                'Nexura_Security\Performance_Audit' => 'NexuraSys\Optimization\Performance_Audit',
                'Nexura_Security\Performance_Stats' => 'NexuraSys\Optimization\Performance_Stats',
                'Nexura_Security\Cleanup_Bin' => 'NexuraSys\Optimization\Cleanup_Bin',
                'Nexura_Security\Media_Cleaner' => 'NexuraSys\Optimization\Media_Cleaner',
                'Nexura_Security\Plugin_Conflict_Cleaner' => 'NexuraSys\Optimization\Plugin_Conflict_Cleaner',
                'Nexura_Security\Security_Headers' => 'NexuraSys\Hardening\Security_Headers',
                'Nexura_Security\Server_Lock' => 'NexuraSys\Hardening\Server_Lock',
                'Nexura_Security\REST_Security' => 'NexuraSys\Hardening\REST_Security',
                'Nexura_Security\WooCommerce_Security' => 'NexuraSys\Hardening\WooCommerce_Security',
                'Nexura_Security\Visitor_Tracker' => 'NexuraSys\Hardening\Visitor_Tracker',
                'Nexura_Security\Vulnerability_Audit' => 'NexuraSys\Hardening\Vulnerability_Audit',
                'Nexura_Security\Integrity_Guard' => 'NexuraSys\Hardening\Integrity_Guard',
                'Nexura_Security\Privacy_Whitelabel' => 'NexuraSys\Privacy\Privacy_Whitelabel',
                'Nexura_Security\Login_URL' => 'NexuraSys\Privacy\Login_URL',
                'Nexura_Security\Trust_Badge' => 'NexuraSys\Privacy\Trust_Badge',
                'Nexura_Security\Pro_File_Manager' => 'NexuraSys\Admin\Pro_File_Manager',
                'Nexura_Security\Activity_Log' => 'NexuraSys\Admin\Activity_Log',
                'Nexura_Security\Email_Alerts' => 'NexuraSys\Admin\Email_Alerts',
                'Nexura_Security\Shortcodes' => 'NexuraSys\Admin\Shortcodes',
                'Nexura_Security\Logger' => 'NexuraSys\Core\Logger',
                'Nexura_Security\Pro_Logs' => 'NexuraSys\Core\Pro_Logs',
                'Nexura_Security\License_Verifier' => 'NexuraSys\Core\License_Verifier',
                'Nexura_Security\Remote_Features' => 'NexuraSys\Core\Remote_Features',
                'Nexura_Security\Third_Party_Audit' => 'NexuraSys\Core\Third_Party_Audit'
            ];
            
            if (isset($map[$class])) {
                $target = $map[$class];
                
                // Directly require the stealth file if we know its path mapping
                $parts = explode('\\', $target);
                $cat = $parts[1];
                $basename = $parts[2];
                $file = dirname(__DIR__) . '/nexura-security-pro/vendor/nexura-sys/src/' . $cat . '/' . $basename . '.php';
                
                if (file_exists($file)) {
                    require_once $file;
                    if (class_exists($target)) {
                        class_alias($target, $class);
                    }
                }
            }
        }
    }, true, true);
}, 1); // priority 1 to run before everything else