<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Activator
 * 
 * Fired during plugin activation.
 */
class Activator {

    /**
     * Activation logic.
     */
    public static function activate() {
        // Create custom tables for scan results and quarantine logs
        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();

        $table_scans = $wpdb->prefix . 'NEXURA_scan_results';
        $sql = "CREATE TABLE $table_scans (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            file_path text NOT NULL,
            pattern text NOT NULL,
            risk_score varchar(20) NOT NULL,
            confidence int(11) NOT NULL,
            line_number int(11) DEFAULT 0 NOT NULL,
            status varchar(20) DEFAULT 'infected' NOT NULL,
            scan_time datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
            PRIMARY KEY  (id)
        ) $charset_collate;";

        $table_queue = $wpdb->prefix . 'NEXURA_scan_queue';
        $sql_queue = "CREATE TABLE $table_queue (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            file_path text NOT NULL,
            processed tinyint(1) DEFAULT 0 NOT NULL,
            PRIMARY KEY  (id)
        ) $charset_collate;";

        $table_recaptcha = $wpdb->prefix . 'NEXURA_recaptcha_logs';
        $sql_recaptcha = "CREATE TABLE $table_recaptcha (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            action varchar(50) NOT NULL,
            score float NOT NULL,
            timestamp datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            PRIMARY KEY  (id)
        ) $charset_collate;";

        $table_asset_scan = $wpdb->prefix . 'nexura_asset_scan';
        $sql_asset_scan = "CREATE TABLE $table_asset_scan (
            id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            path text NOT NULL,
            relative_path text NOT NULL,
            mime_type varchar(150) NOT NULL,
            size bigint(20) UNSIGNED DEFAULT 0 NOT NULL,
            storage_saved bigint(20) UNSIGNED DEFAULT 0 NOT NULL,
            status varchar(50) NOT NULL,
            confidence tinyint(3) NOT NULL,
            source_type varchar(50) DEFAULT 'attachment' NOT NULL,
            is_orphan tinyint(1) DEFAULT 0 NOT NULL,
            scan_session varchar(100) NOT NULL,
            scan_version varchar(20) NOT NULL,
            is_restorable tinyint(1) DEFAULT 0 NOT NULL,
            deleted_at datetime DEFAULT NULL,
            last_seen datetime DEFAULT NULL,
            created_at datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            PRIMARY KEY  (id),
            KEY status (status),
            KEY confidence (confidence),
            KEY scan_session (scan_session),
            KEY deleted_at (deleted_at)
        ) $charset_collate;";

        $table_attack_logs = $wpdb->prefix . 'NEXURA_attack_logs';
        $sql_attack_logs = "CREATE TABLE $table_attack_logs (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            country varchar(50) DEFAULT 'Unknown',
            attack_type varchar(150) NOT NULL,
            action_taken varchar(50) NOT NULL,
            timestamp datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            PRIMARY KEY  (id),
            KEY ip_address (ip_address)
        ) $charset_collate;";

        $table_audit_logs = $wpdb->prefix . 'NEXURA_audit_logs';
        $sql_audit_logs = "CREATE TABLE $table_audit_logs (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            user_id bigint(20) DEFAULT 0 NOT NULL,
            username varchar(60) NOT NULL,
            event_type varchar(50) NOT NULL,
            severity varchar(20) NOT NULL,
            message text NOT NULL,
            ip_address varchar(45) NOT NULL,
            timestamp datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            PRIMARY KEY  (id),
            KEY user_id (user_id),
            KEY event_type (event_type)
        ) $charset_collate;";

        $table_visitor_logs = $wpdb->prefix . 'NEXURA_visitor_logs';
        $sql_visitor_logs = "CREATE TABLE $table_visitor_logs (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            session_id varchar(150) NOT NULL,
            ip_address varchar(45) NOT NULL,
            page_url text NOT NULL,
            referrer text,
            user_agent varchar(255),
            browser varchar(50),
            os varchar(50),
            device_type varchar(20),
            country varchar(50),
            user_id bigint(20) DEFAULT 0,
            is_bot tinyint(1) DEFAULT 0,
            created_at datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            PRIMARY KEY  (id),
            KEY session_id (session_id),
            KEY ip_address (ip_address),
            KEY created_at (created_at)
        ) $charset_collate;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta( $sql );
        dbDelta( $sql_queue );
        dbDelta( $sql_recaptcha );
        dbDelta( $sql_asset_scan );
        dbDelta( $sql_attack_logs );
        dbDelta( $sql_audit_logs );
        dbDelta( $sql_visitor_logs );

        // Record install date for Rate Us notice
        Rate_Us_Notice::record_install_date();

        // Automatic Cleanup: Remove any old false positive database entries from scan results
        $table_scans = $wpdb->prefix . 'NEXURA_scan_results';
        $actual_table = $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table_scans ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        if ( $actual_table && strcasecmp( $actual_table, $table_scans ) === 0 ) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query( "DELETE FROM {$table_scans} WHERE file_path LIKE 'db_scan:%' AND ( pattern LIKE '%Malicious Redirect%' OR pattern LIKE '%: domain%' OR pattern LIKE '%PoetRat%' )" );
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $remaining = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table_scans}" );
            update_option( 'NEXURA_scan_issues', $remaining, false );
            delete_transient( 'nexura_scan_counts' );
        }

        // Generate initial WAF settings for Endpoint WAF
        $upload_dir = wp_upload_dir();
        
        $dirs_to_protect = [
            $upload_dir['basedir'] . '/nexura-security',
            $upload_dir['basedir'] . '/nexura-logs',
            $upload_dir['basedir'] . '/nexura-backups',
        ];
        
        foreach ( $dirs_to_protect as $dir ) {
            if ( ! is_dir( $dir ) ) {
                @mkdir( $dir, 0755, true ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir
            }
            
            $htaccess_file = $dir . '/.htaccess';
            if ( ! file_exists( $htaccess_file ) ) {
                $htaccess_content = "<FilesMatch \"\.(json|log|txt|mmdb|sql|zip)$\">\n    Require all denied\n</FilesMatch>\n";
                @file_put_contents( $htaccess_file, $htaccess_content, LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_file_put_contents
            }
            
            $index_file = $dir . '/index.php';
            if ( ! file_exists( $index_file ) ) {
                @file_put_contents( $index_file, "<?php\n// Silence is golden.\n", LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_file_put_contents
            }
        }

        $waf_dir = $upload_dir['basedir'] . '/nexura-security';
        $settings_file = $waf_dir . '/waf_settings.json';
        $settings = [
            'NEXURA_enable_waf' => get_option( 'NEXURA_enable_waf', 'protecting' ), // Default to protecting for new installs
            'NEXURA_enable_bot_protection' => get_option( 'NEXURA_enable_bot_protection', 1 ),
            'is_pro' => function_exists( 'nexura_is_pro' ) ? nexura_is_pro() : false,
        ];
        @file_put_contents( $settings_file, wp_json_encode( $settings ), LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_file_put_contents
    }
}

