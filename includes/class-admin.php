<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Admin
 * 
 * Handles the admin dashboard interface, menu registration, and enqueuing assets.
 */
class Admin {

    /**
     * Initializes admin hooks.
     */
    public function init() {
        add_action( 'admin_init', [ $this, 'register_settings' ] );
        add_action( 'admin_init', [ $this, 'run_migrations' ] );
        add_action( 'admin_menu', [ $this, 'register_menus' ] );
        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_assets' ] );


    }

    /**
     * Renders McAfee-style persistent upsell notice when malware is found.
     */


    /**
     * Checks database schema and updates if necessary.
     */
    public function run_migrations() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'NEXURA_scan_results';
        
        // Ensure scan results table exists before checking columns
        if ( $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table_name ) ) === $table_name ) { // phpcs:ignore WordPress.DB.DirectDatabaseQuery
            $row = $wpdb->get_results( "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '{$wpdb->prefix}NEXURA_scan_results' AND COLUMN_NAME = 'line_number'" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
            if ( empty( $row ) ) {
                $wpdb->query( "ALTER TABLE {$wpdb->prefix}NEXURA_scan_results ADD COLUMN line_number int(11) DEFAULT 0 NOT NULL AFTER confidence" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.DirectDatabaseQuery
            }
        }

        // Create Activity Logs table
        $activity_table = $wpdb->prefix . 'NEXURA_activity_logs';
        $activity_table_exists = $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $activity_table ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        if ( ! $activity_table_exists || strcasecmp( $activity_table_exists, $activity_table ) !== 0 ) {
            $charset_collate = $wpdb->get_charset_collate();
            $sql = "CREATE TABLE $activity_table (
                id bigint(20) NOT NULL AUTO_INCREMENT,
                user_id bigint(20) NOT NULL,
                action varchar(100) NOT NULL,
                object_name varchar(255) NOT NULL,
                ip_address varchar(45) NOT NULL,
                created_at datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
                PRIMARY KEY  (id),
                KEY user_id (user_id),
                KEY action (action)
            ) $charset_collate;";
            require_once ABSPATH . 'wp-admin/includes/upgrade.php';
            dbDelta( $sql );
        }

        // Create Threat IPs table
        $threat_table = $wpdb->prefix . 'NEXURA_threat_ips';
        $threat_table_exists = $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $threat_table ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        if ( ! $threat_table_exists || strcasecmp( $threat_table_exists, $threat_table ) !== 0 ) {
            $charset_collate = $wpdb->get_charset_collate();
            $sql = "CREATE TABLE $threat_table (
                id bigint(20) NOT NULL AUTO_INCREMENT,
                ip_address varchar(45) NOT NULL,
                threat_score int(11) NOT NULL,
                updated_at datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
                PRIMARY KEY  (id),
                UNIQUE KEY ip_address (ip_address)
            ) $charset_collate;";
            require_once ABSPATH . 'wp-admin/includes/upgrade.php';
            dbDelta( $sql );
        }
    }

    /**
     * Registers settings options.
     */
    public function register_settings() {
        $sanitize_args = [ 'sanitize_callback' => 'sanitize_text_field' ];
        register_setting( 'NEXURA_settings_group', 'NEXURA_google_api_key', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_virustotal_api_key', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_custom_login_slug', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_scan_core', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_scan_plugins', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_scan_themes', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_scan_uploads', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_delete_data_on_uninstall', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_enable_trust_badge_footer', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_enable_pwned_check', $sanitize_args );
        // Hardening settings
        register_setting( 'NEXURA_hardening_group', 'NEXURA_disable_file_editor', $sanitize_args );
        register_setting( 'NEXURA_hardening_group', 'NEXURA_add_security_headers', $sanitize_args );
        register_setting( 'NEXURA_ssl_group', 'NEXURA_force_ssl', $sanitize_args );
        register_setting( 'NEXURA_hardening_group', 'NEXURA_restrict_rest_api', $sanitize_args );
        
        // .htaccess Hardening settings (in settings group since they are in the settings form)
        register_setting( 'NEXURA_settings_group', 'NEXURA_htaccess_file', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_htaccess_xmlrpc', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_htaccess_signature', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_htaccess_author', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_wpscan_api_key', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_enable_auto_heal', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_enable_waf', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_enable_threat_intel', $sanitize_args );
        
        // Login Security / reCAPTCHA Settings
        register_setting( 'NEXURA_login_security_group', 'NEXURA_2fa_roles', [ 'type' => 'array', 'sanitize_callback' => [ $this, 'sanitize_2fa_roles' ] ] );
        register_setting( 'NEXURA_login_security_group', 'NEXURA_2fa_grace_period', $sanitize_args );
        register_setting( 'NEXURA_login_security_group', 'NEXURA_disable_xmlrpc', $sanitize_args );
        register_setting( 'NEXURA_login_security_group', 'NEXURA_require_xmlrpc_2fa', $sanitize_args );
        register_setting( 'NEXURA_login_security_group', 'NEXURA_recaptcha_enabled', $sanitize_args );
        register_setting( 'NEXURA_login_security_group', 'NEXURA_recaptcha_site_key', $sanitize_args );
        register_setting( 'NEXURA_login_security_group', 'NEXURA_recaptcha_secret_key', $sanitize_args );
        register_setting( 'NEXURA_login_security_group', 'NEXURA_recaptcha_threshold', $sanitize_args );
        register_setting( 'NEXURA_login_security_group', 'NEXURA_recaptcha_test_mode', $sanitize_args );
        register_setting( 'NEXURA_login_security_group', 'NEXURA_ip_allowlist', [ 'sanitize_callback' => 'sanitize_textarea_field' ] );
        
        // New Login Security Settings
        register_setting( 'NEXURA_login_security_group', 'NEXURA_allow_remember_device', $sanitize_args );
        register_setting( 'NEXURA_login_security_group', 'NEXURA_wc_integration', $sanitize_args );
        register_setting( 'NEXURA_login_security_group', 'NEXURA_wc_account_menu', $sanitize_args );
        register_setting( 'NEXURA_login_security_group', 'NEXURA_2fa_shortcode', $sanitize_args );
        register_setting( 'NEXURA_login_security_group', 'NEXURA_wc_single_column', $sanitize_args );
        register_setting( 'NEXURA_login_security_group', 'NEXURA_ntp_sync', $sanitize_args );
        register_setting( 'NEXURA_login_security_group', 'NEXURA_show_last_login', $sanitize_args );
        register_setting( 'NEXURA_login_security_group', 'NEXURA_delete_data_on_deactivation', $sanitize_args );
        
        // Manage Auto-Heal Drop-in on Option Update
        add_action( 'update_option_NEXURA_enable_auto_heal', [ $this, 'manage_auto_heal_dropin' ], 10, 3 );
        add_action( 'add_option_NEXURA_enable_auto_heal', [ $this, 'manage_auto_heal_dropin_add' ], 10, 2 );

        // Schedule Core Backup download when WAF is enabled
        add_action( 'update_option_NEXURA_enable_waf', [ $this, 'schedule_core_backup_download' ], 10, 3 );
        add_action( 'add_option_NEXURA_enable_waf', [ $this, 'schedule_core_backup_download_add' ], 10, 2 );
        add_action( 'nexura_download_core_backup', [ $this, 'download_core_backup' ] );
    }

    public function schedule_core_backup_download_add( $option, $value ) {
        $this->schedule_core_backup_download( '', $value, $option );
    }

    public function schedule_core_backup_download( $old_value, $value, $option ) {
        if ( '1' === $value ) {
            if ( ! wp_next_scheduled( 'nexura_download_core_backup' ) ) {
                wp_schedule_single_event( time(), 'nexura_download_core_backup' );
            }
        }
    }

    public function download_core_backup() {
        require_once ABSPATH . 'wp-admin/includes/file.php';
        WP_Filesystem();
        global $wp_filesystem;
        
        $backup_dir = wp_upload_dir()['basedir'] . '/nexura-security';
        if ( ! $wp_filesystem->exists( $backup_dir ) ) {
            $wp_filesystem->mkdir( $backup_dir );
        }
        
        $local_zip = $backup_dir . '/core-backup.zip';
        
        // Don't download if we already have it
        if ( $wp_filesystem->exists( $local_zip ) ) {
            return;
        }

        $zip_url = 'https://wordpress.org/latest.zip';
        $response = wp_remote_get( $zip_url, [ 'timeout' => 300 ] ); // 5 minutes timeout for large file
        
        if ( ! is_wp_error( $response ) && wp_remote_retrieve_response_code( $response ) === 200 ) {
            $wp_filesystem->put_contents( $local_zip, wp_remote_retrieve_body( $response ), FS_CHMOD_FILE );
        }
    }

    public function manage_auto_heal_dropin_add( $option, $value ) {
        $this->manage_auto_heal_dropin( '', $value, $option );
    }

    public function manage_auto_heal_dropin( $old_value, $value, $option ) {
        require_once ABSPATH . 'wp-admin/includes/file.php';
        WP_Filesystem();
        global $wp_filesystem;
        
        $dropin_dest = WP_CONTENT_DIR . '/fatal-error-handler.php';
        $dropin_src  = NEXURA_PLUGIN_DIR . 'drop-ins/fatal-error-handler.php';

        if ( '1' === $value ) {
            // Check if there is an existing dropin not owned by us
            if ( $wp_filesystem->exists( $dropin_dest ) ) {
                $content = $wp_filesystem->get_contents( $dropin_dest );
                if ( strpos( $content, 'Nexura Security' ) === false ) {
                    // Do not overwrite other plugins' dropins silently, we could log it or show an error
                    return;
                }
            }
            $wp_filesystem->copy( $dropin_src, $dropin_dest, true, FS_CHMOD_FILE );
        } else {
            if ( $wp_filesystem->exists( $dropin_dest ) ) {
                $content = $wp_filesystem->get_contents( $dropin_dest );
                if ( strpos( $content, 'Nexura Security' ) !== false ) {
                    $wp_filesystem->delete( $dropin_dest );
                }
            }
        }
    }

    public function sanitize_array( $input ) {
        if ( ! is_array( $input ) ) return [];
        return array_map( 'sanitize_text_field', $input );
    }

    public function sanitize_2fa_roles( $input ) {
        if ( ! is_array( $input ) ) return [];
        
        $sanitized = [];
        $valid_values = [ 'optional', 'required', 'disabled' ];
        
        foreach ( $input as $role => $value ) {
            $clean_role = sanitize_key( $role );
            if ( in_array( $value, $valid_values, true ) ) {
                $sanitized[ $clean_role ] = $value;
            }
        }
        
        return $sanitized;
    }


    /**
     * Registers the plugin admin menu.
     */
    public function register_menus() {
        add_menu_page(
            __( 'Nexura', 'nexura-security' ),
            __( 'Nexura', 'nexura-security' ),
            'manage_options',
            'nexura',
            [ $this, 'render_dashboard' ],
            'dashicons-shield',
            80
        );

        $submenu_pages = [
            'dashboard'            => __( 'Dashboard', 'nexura-security' ),
            'malware-scan'         => __( 'Malware Scan', 'nexura-security' ),
            'issues-detected'      => __( 'Issues Detected', 'nexura-security' ),
            'file-integrity'       => __( 'File Integrity', 'nexura-security' ),
            'hardening'            => __( 'Hardening', 'nexura-security' ),
            'google-safe-browsing' => __( 'Google Safe Browsing', 'nexura-security' ),
            'settings'             => __( 'Settings', 'nexura-security' ),
            'login-security'       => __( 'Login Security', 'nexura-security' ),
            'ssl-settings'         => __( 'SSL & HTTPS', 'nexura-security' ),
            'about'                => __( 'About', 'nexura-security' ),
        ];

        foreach ( $submenu_pages as $slug => $title ) {
            add_submenu_page(
                'nexura',
                $title . ' &lsaquo; ' . __( 'Nexura', 'nexura-security' ),
                $title,
                'manage_options',
                'nexura-' . $slug,
                [ $this, 'render_view' ]
            );
        }
    }

    /**
     * Enqueues admin CSS and JS.
     */
    public function enqueue_assets( $hook_suffix ) {
        if ( strpos( $hook_suffix, 'nexura' ) === false && ! in_array( $hook_suffix, [ 'profile.php', 'user-edit.php' ], true ) ) {
            return;
        }

        // Google Fonts - Inter (Loaded locally from admin-style.css)
        // wp_enqueue_style( 'nexura-google-fonts', 'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap', [], '1.0.0' );

        // Enqueue WP Code Editor (CodeMirror) for PHP files
        $code_editor_settings = wp_enqueue_code_editor( array( 'type' => 'text/x-php' ) );

        // Chart.js (Loaded locally to comply with WordPress org guidelines)
        wp_enqueue_script( 'nexura-chartjs', NEXURA_PLUGIN_URL . 'admin/js/chart.umd.min.js', [], '4.4.1', true );
        
        // QR Code
        wp_enqueue_script( 'nexura-qrcode', NEXURA_PLUGIN_URL . 'admin/js/qrcode.min.js', [], NEXURA_VERSION, true );

        wp_enqueue_style( 'nexura-admin-style', NEXURA_PLUGIN_URL . 'admin/css/admin-style.css', [], NEXURA_VERSION );
        wp_enqueue_style( 'nexura-pro-upgrade-modal', NEXURA_PLUGIN_URL . 'admin/css/pro-upgrade-modal.css', [ 'nexura-admin-style' ], NEXURA_VERSION );
        wp_enqueue_script( 'nexura-admin-script', NEXURA_PLUGIN_URL . 'admin/js/admin-script.js', [ 'jquery', 'nexura-chartjs', 'nexura-qrcode' ], time(), true );
        wp_enqueue_script( 'nexura-malware-scan-cpu', NEXURA_PLUGIN_URL . 'admin/js/malware-scan-cpu.js', [], NEXURA_VERSION, true );

        // Collect dashboard data for charts
        global $wpdb;
        $table_name   = $wpdb->prefix . 'NEXURA_scan_results';
        
        if ( class_exists( '\Nexura_Security\Scanner' ) ) {
            \Nexura_Security\Scanner::auto_heal_scan_results();
        }
        
        $cached_counts = wp_cache_get( 'nexura_scan_counts', 'nexura' );
        if ( false === $cached_counts ) {
            $high_count   = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table_name} WHERE risk_score = %s", 'High' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $medium_count = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table_name} WHERE risk_score = %s", 'Medium' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $total_count  = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table_name}" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            
            $cached_counts = compact( 'high_count', 'medium_count', 'total_count' );
            wp_cache_set( 'nexura_scan_counts', $cached_counts, 'nexura', 300 );
        } else {
            $high_count = $cached_counts['high_count'];
            $medium_count = $cached_counts['medium_count'];
            $total_count = $cached_counts['total_count'];
        }

        $clean_count  = max( 0, (int) get_option( 'NEXURA_scan_total', 0 ) - $total_count );

        $queue       = get_option( 'NEXURA_scan_queue', [] );
        $processed   = (int) get_option( 'NEXURA_scan_processed', 0 );
        $scan_total  = (int) get_option( 'NEXURA_scan_total', 0 );
        $scan_issues = (int) get_option( 'NEXURA_scan_issues', 0 );
        $progress    = $scan_total > 0 ? round( ( $processed / $scan_total ) * 100 ) : 0;
        
        $plan = nexura_is_pro() ? 'pro' : 'free';

        $upgrade_url = function_exists('nexurasec_fs') ? nexurasec_fs()->get_upgrade_url() : 'https://nexurasecurity.com/pricing';

        $recaptcha_stats = [
            'labels' => [],
            'humans' => [],
            'bots'   => []
        ];

        // Fetch reCAPTCHA stats if table exists
        $table_recaptcha = $wpdb->prefix . 'NEXURA_recaptcha_logs';
        if ( $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table_recaptcha ) ) === $table_recaptcha ) { // phpcs:ignore WordPress.DB.DirectDatabaseQuery
            $threshold = (float) get_option( 'NEXURA_recaptcha_threshold', '0.5' );
            for ( $i = 6; $i >= 0; $i-- ) {
                $date = gmdate( 'Y-m-d', strtotime( "-$i days" ) );
                $display_date = gmdate( 'M j', strtotime( "-$i days" ) );
                $recaptcha_stats['labels'][] = $display_date;
                
                $human_count = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}NEXURA_recaptcha_logs WHERE DATE(timestamp) = %s AND score >= %f", $date, $threshold ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
                $bot_count   = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}NEXURA_recaptcha_logs WHERE DATE(timestamp) = %s AND score < %f", $date, $threshold ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
                
                $recaptcha_stats['humans'][] = $human_count;
                $recaptcha_stats['bots'][]   = $bot_count;
            }
        }

        // Fetch malware trend
        $malware_trend = [
            'labels' => [],
            'high'   => [],
            'medium' => []
        ];
        
        if ( $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table_name ) ) === $table_name ) { // phpcs:ignore WordPress.DB.DirectDatabaseQuery
            for ( $i = 6; $i >= 0; $i-- ) {
                $date = gmdate( 'Y-m-d', strtotime( "-$i days" ) );
                $display_date = gmdate( 'M j', strtotime( "-$i days" ) );
                $malware_trend['labels'][] = $display_date;
                
                $high = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table_name} WHERE DATE(scan_time) = %s AND risk_score = %s", $date, 'High' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
                $medium = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table_name} WHERE DATE(scan_time) = %s AND risk_score = %s", $date, 'Medium' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
                
                $malware_trend['high'][] = $high;
                $malware_trend['medium'][] = $medium;
            }
        }
        
        // FIM Data
        $fim_data = [ 'core' => 0, 'plugins' => 0, 'themes' => 0 ];
        $upload_dir = wp_upload_dir();
        $baseline_file = trailingslashit( $upload_dir['basedir'] ) . 'nexura-logs/fim-baseline.json';
        if ( file_exists( $baseline_file ) ) {
            $baseline = json_decode( file_get_contents( $baseline_file ), true );
            if ( is_array( $baseline ) ) {
                foreach ( $baseline as $file => $hash ) {
                    if ( strpos( $file, 'wp-content/plugins' ) !== false ) {
                        $fim_data['plugins']++;
                    } elseif ( strpos( $file, 'wp-content/themes' ) !== false ) {
                        $fim_data['themes']++;
                    } else {
                        $fim_data['core']++;
                    }
                }
            }
        }


        $is_license_active = false;
        if ( class_exists( '\Nexura_Security\License_Verifier' ) ) {
            $is_license_active = \Nexura_Security\License_Verifier::is_verified();
        }

        wp_localize_script( 'nexura-admin-script', 'NEXURA_ajax', [
            'rest_url'       => esc_url_raw( rest_url() ),
            'rest_route_url' => esc_url_raw( get_rest_url( null, '', 'rest' ) ),
            'site_url'       => esc_url_raw( site_url( '/' ) ),
            'ajax_url'       => esc_url_raw( admin_url( 'admin-ajax.php' ) ),
            'nonce'          => wp_create_nonce( 'wp_rest' ),
            'plan'           => $plan,
            'high_issues'    => $high_count,
            'medium_issues'  => $medium_count,
            'total_issues'   => $total_count,
            'clean_files'    => $clean_count,
            'scan_running'   => ! empty( $queue ),
            'scan_progress'  => $progress,
            'scan_processed' => $processed,
            'scan_total'     => $scan_total,
            'scan_issues'    => $scan_issues,
            'upgrade_url'    => $upgrade_url,
            'code_editor'    => $code_editor_settings,
            'recaptcha_stats'=> $recaptcha_stats,
            'malware_trend'  => $malware_trend,
            'fim_data'       => $fim_data,
            'is_license_active' => $is_license_active,
            'pro_slugs'      => [
                'nexura-active-monitoring', 'nexura-vulnerability-audit', 'nexura-third-party-audit',
                'nexura-performance', 'nexura-file-snapshots', 'nexura-logs', 'nexura-security-headers',
                'nexura-rest-security', 'nexura-plugin-cleaner', 'nexura-db-optimizer'
            ],
            'backup_nonce'   => wp_create_nonce( 'nexura_db_backup' )
        ] );
    }

    /**
     * Renders the main dashboard view.
     */
    public function render_dashboard() {
        if ( class_exists( '\Nexura_Security\Scanner' ) ) {
            \Nexura_Security\Scanner::auto_heal_scan_results();
        }
        
        $this->load_view( 'dashboard' );
    }



    /**
     * Renders sub-views dynamically based on the page slug.
     */
    public function render_view() {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $page = isset( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : '';
        $view = str_replace( 'nexura-', '', $page );

        if ( class_exists( '\Nexura_Security\Scanner' ) ) {
            \Nexura_Security\Scanner::auto_heal_scan_results();
        }

        $this->load_view( $view );
    }

    /**
     * Loads a view file safely.
     *
     * @param string $view Name of the view file (without .php).
     */
    private function load_view( $view ) {
        if ( 'login-security' === $view ) {
            $file = NEXURA_PLUGIN_DIR . 'admin/views/login-security-main.php';
        } else {
            $file = NEXURA_PLUGIN_DIR . 'admin/views/' . $view . '.php';
        }

        if ( file_exists( $file ) ) {
            require NEXURA_PLUGIN_DIR . 'admin/views/partials/header.php';
            require $file;
            require NEXURA_PLUGIN_DIR . 'admin/views/partials/footer.php';
        } else {
            echo '<div class="notice notice-error"><p>View not found: ' . esc_html( $view ) . '</p></div>';
        }
    }

}
