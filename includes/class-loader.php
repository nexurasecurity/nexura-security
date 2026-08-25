<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Loader
 * 
 * Orchestrates the loading and initialization of all core plugin modules.
 */
class Loader {

    /**
     * Initializes the plugin components.
     */
    public function run() {
        require_once NEXURA_PLUGIN_DIR . 'includes/class-security-score.php';
        
        // Auto-run cleanup for upgrading users once
        $db_version = get_option( 'NEXURA_db_version', '1.0.0' );
        if ( version_compare( $db_version, '1.0.12', '<' ) ) {
            global $wpdb;
            $table_scans = $wpdb->prefix . 'NEXURA_scan_results';
            // Check if table exists before running queries
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            if ( $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table_scans ) ) === $table_scans ) {
                $wpdb->query(
                    "DELETE FROM {$table_scans} WHERE file_path LIKE 'db_scan:%' AND (
                        pattern LIKE '%Malicious Redirect%'
                        OR pattern LIKE '%: domain%'
                        OR pattern LIKE '%PoetRat%'
                    )"
                );
                $remaining = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table_scans}" );
                update_option( 'NEXURA_scan_issues', $remaining, false );
                wp_cache_delete( 'nexura_scan_counts', 'nexura' );
            }
            update_option( 'NEXURA_db_version', '1.0.12' );
        }

        $this->init_modules();
    }

    /**
     * Load all modules.
     */
    private function init_modules() {
        $admin = new Admin();
        if ( is_admin() ) {
            $admin->init();
            new Rate_Us_Notice(); // Show "Rate Us" notice after 14 days
        }
        // Load admin bar notification on both frontend and backend
        add_action( 'admin_bar_menu', [ $admin, 'add_admin_bar_notification' ], 999 );

        // Core engines (Always load)
        if ( file_exists( NEXURA_PLUGIN_DIR . 'includes/class-waf.php' ) ) {
            require_once NEXURA_PLUGIN_DIR . 'includes/class-waf.php';
        }
        if ( class_exists( 'Nexura_Security\WAF' ) ) {
            $waf = new WAF();
            $waf->init();
        }

        if ( class_exists( 'Nexura_Security\Global_Threat_Intel' ) ) {
            $threat_intel = new Global_Threat_Intel();
        }
        if ( class_exists( 'Nexura_Security\Hardening' ) ) {
            $hardening = new Hardening();
            $hardening->apply_rules();
            if ( is_admin() ) {
                $hardening->init_hooks();
            }
        }
        if ( class_exists( 'Nexura_Security\Ghost_Admin_Protection' ) ) {
            $ghost_admin = new Ghost_Admin_Protection();
        }
        
        $cron = new Cron();
        $cron->init();

        $security_headers = new Security_Headers();
        if ( method_exists( $security_headers, 'init' ) ) {
            $security_headers->init();
        }

        // Auth & Frontend Security
        $login_protection = new Login_Protection();
        $login_protection->init();
        $two_factor = new Two_Factor_Auth();
        $two_factor->init();
        $pwned_passwords = new Pwned_Passwords();
        $pwned_passwords->init();
        $anti_spam = new Anti_Spam();
        $anti_spam->init();
        $session_manager = new Session_Manager();
        $session_manager->init();
        $magic_link = new Magic_Link();
        $magic_link->init();
        
        $recaptcha = new reCAPTCHA();
        $recaptcha->init();
        
        $login_security = new Login_Security();
        $login_security->init();
        
        if ( class_exists( 'Nexura_Security\Login_Security_Integrations' ) ) {
            $login_security_integrations = new Login_Security_Integrations();
            $login_security_integrations->init();
        }

        $audit_logger_file = plugin_dir_path( dirname( __FILE__ ) ) . 'includes/class-audit-logger.php';
        if ( file_exists( $audit_logger_file ) ) {
            require_once $audit_logger_file;
            if ( class_exists( 'Nexura_Security\Audit_Logger' ) ) {
                $audit_logger = new Audit_Logger();
                $audit_logger->init();
            }
        }

        // Admin & Background Processes Only
        if ( is_admin() || ( defined( 'DOING_CRON' ) && DOING_CRON ) || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
            
            if ( file_exists( NEXURA_PLUGIN_DIR . 'includes/class-scanner.php' ) ) {
                require_once NEXURA_PLUGIN_DIR . 'includes/class-scanner.php';
            }
            if ( class_exists( 'Nexura_Security\Scanner' ) ) {
                $scanner = new Scanner();
            }
            if ( class_exists( 'Nexura_Security\Real_Time_Scan' ) ) {
                $real_time_scan = new Real_Time_Scan();
            }
            if ( class_exists( 'Nexura_Security\File_Integrity' ) ) {
                $file_integrity = new File_Integrity();
            }
            if ( class_exists( 'Nexura_Security\DB_Backup' ) ) {
                $db_backup = new DB_Backup();
                $db_backup->init();
            }
            
            if ( file_exists( NEXURA_PLUGIN_DIR . 'includes/class-safe-cleanup.php' ) ) {
                require_once NEXURA_PLUGIN_DIR . 'includes/class-safe-cleanup.php';
            }
            if ( class_exists( 'Nexura_Security\Safe_Cleanup' ) ) {
                $safe_cleanup = new Safe_Cleanup();
            }

            if ( file_exists( NEXURA_PLUGIN_DIR . 'includes/class-cron-audit.php' ) ) {
                require_once NEXURA_PLUGIN_DIR . 'includes/class-cron-audit.php';
            }
            
            if ( file_exists( NEXURA_PLUGIN_DIR . 'includes/class-vulnerability-scanner.php' ) ) {
                require_once NEXURA_PLUGIN_DIR . 'includes/class-vulnerability-scanner.php';
            }
            if ( class_exists( 'Nexura_Security\Vulnerability_Scanner' ) ) {
                $vuln_scanner = new Vulnerability_Scanner();
                $vuln_scanner->init();
            }
        }

        // REST API
        if ( class_exists( 'Nexura_Security\Rest_Controller' ) ) {
            add_action( 'rest_api_init', [ new Rest_Controller(), 'register_routes' ] );
        }
    }
}
