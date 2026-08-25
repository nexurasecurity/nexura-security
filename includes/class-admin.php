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
    public function render_free_sidebar_menus( $current_slug ) {
        // Output the free Security Headers menu item if Pro is not active
        if ( ! nexura_is_pro() ) {
            $active_class = ( $current_slug === 'security-headers' ) ? 'active' : '';
            echo '<a href="' . esc_url( admin_url( 'admin.php?page=nexura-security-headers' ) ) . '" class="nexura-nav-item ' . esc_attr( $active_class ) . '">';
            echo '<span class="nexura-nav-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg></span> Security Headers';
            echo '</a>';
        }
    }

    public function init() {
        add_action( 'admin_init', [ $this, 'register_settings' ] );
        add_action( 'admin_init', [ $this, 'run_migrations' ] );
        add_action( 'admin_init', [ $this, 'handle_report_download' ] );
        add_action( 'admin_init', [ $this, 'handle_settings_export_import' ] );
        add_action( 'admin_menu', [ $this, 'register_menus' ] );
        
        // Output free version specific menus in the custom sidebar
        add_action( 'nexura_free_sidebar_menus', [ $this, 'render_free_sidebar_menus' ] );

        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_assets' ] );
        add_action( 'wp_dashboard_setup', [ $this, 'register_dashboard_widget' ] );
        add_action( 'post_submitbox_start', [ $this, 'render_post_submitbox_marketing' ] );

        // Suppress ALL admin notices on Nexura pages (Freemius, WordPress core, other plugins).
        // We hook at PHP_INT_MIN so we run FIRST inside do_action('admin_notices') and
        // remove every other callback before it can output anything.
        add_action( 'current_screen', function() {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $page = isset( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : '';
            if ( strpos( $page, 'nexura' ) === false ) {
                return;
            }
            add_action( 'admin_notices', function() {
                global $wp_filter;
                if ( isset( $wp_filter['admin_notices'] ) ) {
                    foreach ( array_keys( $wp_filter['admin_notices']->callbacks ) as $priority ) {
                        // Keep only our own suppressor (priority = PHP_INT_MIN)
                        if ( $priority !== PHP_INT_MIN ) {
                            unset( $wp_filter['admin_notices']->callbacks[ $priority ] );
                        }
                    }
                }
            }, PHP_INT_MIN );
            remove_all_actions( 'all_admin_notices' );
            remove_all_actions( 'user_admin_notices' );
        } );
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
     * Handles the on-demand download of the PDF scan report.
     */
    public function handle_report_download() {
        if ( isset( $_GET['nexura_download_report'] ) && $_GET['nexura_download_report'] == '1' ) {
            // Verify nonce
            if ( ! isset( $_GET['_wpnonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ), 'nexura_download_report_action' ) ) {
                wp_die( esc_html__( 'Security check failed.', 'nexura-security' ) );
            }

            // Verify permissions
            if ( ! current_user_can( 'manage_options' ) ) {
                wp_die( esc_html__( 'You do not have permission to download this report.', 'nexura-security' ) );
            }

            // Require Report Generator
            require_once NEXURA_PLUGIN_DIR . 'includes/class-report-generator.php';
            
            global $wpdb;
            $table_name    = $wpdb->prefix . 'NEXURA_scan_results';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $issues        = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table_name}" );
            $processed     = (int) get_option( 'NEXURA_scan_total', 0 );

            $response = [
                'issues'    => $issues,
                'processed' => $processed,
            ];

            // Clean output buffer before generating PDF
            while ( ob_get_level() ) {
                ob_end_clean();
            }

            \Nexura_Security\Report_Generator::generate_and_send( $response, true ); // Passing true to download instead of email
            exit;
        }
    }

    /**
     * Handles export and import of settings.
     */
    public function handle_settings_export_import() {
        // Handle Export
        if ( isset( $_GET['nexura_export_settings'] ) && $_GET['nexura_export_settings'] == '1' ) {
            if ( ! isset( $_GET['_wpnonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ), 'nexura_export_settings_action' ) ) {
                wp_die( esc_html__( 'Security check failed.', 'nexura-security' ) );
            }
            if ( ! current_user_can( 'manage_options' ) ) {
                wp_die( esc_html__( 'You do not have permission to export settings.', 'nexura-security' ) );
            }

            global $wpdb;
            $options = $wpdb->get_results( "SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE 'NEXURA_%' AND option_name NOT LIKE '\_transient%'" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

            $export_data = [];
            foreach ( $options as $option ) {
                $export_data[ $option->option_name ] = maybe_unserialize( $option->option_value );
            }

            $json_data = wp_json_encode( $export_data, JSON_PRETTY_PRINT );

            while ( ob_get_level() ) {
                ob_end_clean();
            }

            header( 'Content-Description: File Transfer' );
            header( 'Content-Type: application/json; charset=' . get_option( 'blog_charset' ) );
            header( 'Content-Disposition: attachment; filename="nexura-settings-export-' . current_time( 'Y-m-d' ) . '.json"' );
            header( 'Content-Length: ' . strlen( $json_data ) );
            
            echo $json_data; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            exit;
        }

        // Handle Import
        if ( isset( $_POST['nexura_import_settings_submit'] ) && isset( $_FILES['nexura_import_file'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
            if ( ! isset( $_POST['nexura_import_settings_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['nexura_import_settings_nonce'] ) ), 'nexura_import_settings_action' ) ) {
                wp_die( esc_html__( 'Security check failed.', 'nexura-security' ) );
            }
            if ( ! current_user_can( 'manage_options' ) ) {
                wp_die( esc_html__( 'You do not have permission to import settings.', 'nexura-security' ) );
            }

            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
            $file = $_FILES['nexura_import_file'];
            if ( $file['error'] !== UPLOAD_ERR_OK || empty( $file['tmp_name'] ) ) {
                wp_die( esc_html__( 'Error uploading file.', 'nexura-security' ) );
            }

            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
            $json_data = file_get_contents( $file['tmp_name'] );
            $import_data = json_decode( $json_data, true );

            if ( ! is_array( $import_data ) ) {
                wp_die( esc_html__( 'Invalid settings file.', 'nexura-security' ) );
            }

            foreach ( $import_data as $key => $value ) {
                if ( strpos( $key, 'NEXURA_' ) === 0 ) {
                    update_option( sanitize_text_field( $key ), $value );
                }
            }

            wp_safe_redirect( add_query_arg( [ 'page' => 'nexura-settings', 'imported' => 'true' ], admin_url( 'admin.php' ) ) );
            exit;
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
        register_setting( 'NEXURA_settings_group', 'NEXURA_enable_smart_scan', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_delete_data_on_uninstall', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_enable_trust_badge_footer', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_enable_pwned_check', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_hide_third_party_notices', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_enable_magic_link', $sanitize_args );
        
        // Brute-force settings
        register_setting( 'NEXURA_settings_group', 'NEXURA_brute_force_max_attempts', [ 'sanitize_callback' => 'absint' ] );
        register_setting( 'NEXURA_settings_group', 'NEXURA_brute_force_lockout', [ 'sanitize_callback' => 'absint' ] );
        
        // Hardening settings
        register_setting( 'NEXURA_hardening_group', 'NEXURA_disable_file_editor', $sanitize_args );
        register_setting( 'NEXURA_hardening_group', 'block_php_uploads', $sanitize_args );
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
        
        // Alert System settings
        register_setting( 'NEXURA_settings_group', 'NEXURA_enable_email_alerts', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_alert_email_address', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_email_alerts_critical', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_email_alerts_high', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_email_alerts_medium', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_enable_webhook_alerts', $sanitize_args );
        register_setting( 'NEXURA_settings_group', 'NEXURA_webhook_url', [ 'sanitize_callback' => 'esc_url_raw' ] );
        
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

        // Security Headers Settings
        register_setting( 'NEXURA_security_headers_group', 'NEXURA_sh_enable_all', $sanitize_args );
        register_setting( 'NEXURA_security_headers_group', 'NEXURA_sh_x_frame_options', $sanitize_args );
        register_setting( 'NEXURA_security_headers_group', 'NEXURA_sh_x_xss_protection', $sanitize_args );
        register_setting( 'NEXURA_security_headers_group', 'NEXURA_sh_x_content_type_options', $sanitize_args );
        register_setting( 'NEXURA_security_headers_group', 'NEXURA_sh_strict_transport_security', $sanitize_args );
        register_setting( 'NEXURA_security_headers_group', 'NEXURA_sh_referrer_policy', $sanitize_args );
        register_setting( 'NEXURA_security_headers_group', 'NEXURA_sh_permissions_policy', [ 'sanitize_callback' => 'sanitize_text_field' ] );
        register_setting( 'NEXURA_security_headers_group', 'NEXURA_sh_content_security_policy', [ 'sanitize_callback' => 'sanitize_textarea_field' ] );

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
            '3.14159'
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
            'audit-logs'           => __( 'Audit Logs', 'nexura-security' ),
            'cron-audit'           => __( 'Cron Audit', 'nexura-security' ),
            'db-security'          => __( 'Database Security', 'nexura-security' ),
            'ssl-settings'         => __( 'SSL & HTTPS', 'nexura-security' ),
            'about'                => __( 'About', 'nexura-security' ),
            'contact'              => __( 'Contact Us', 'nexura-security' ),
        ];

        // Only add Free Security Headers menu if Pro is not installed/active
        if ( ! nexura_is_pro() ) {
            // Insert it after hardening
            $submenu_pages = array_slice( $submenu_pages, 0, 5, true ) +
                [ 'security-headers' => __( 'Security Headers', 'nexura-security' ) ] +
                array_slice( $submenu_pages, 5, null, true );
        }

        // Define which slugs should be visible in the native WordPress sidebar
        $visible_slugs = [ 'dashboard', 'settings', 'about', 'contact' ];

        foreach ( $submenu_pages as $slug => $title ) {
            $parent = in_array( $slug, $visible_slugs, true ) ? 'nexura' : 'nexura_hidden';
            
            add_submenu_page(
                $parent,
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
        // Global notice removal (if switch is ON)
        if ( get_option( 'NEXURA_hide_third_party_notices' ) === '1' ) {
            remove_all_actions( 'admin_notices' );
            remove_all_actions( 'all_admin_notices' );
            add_action( 'admin_notices', 'settings_errors' );
        }

        if ( strpos( $hook_suffix, 'nexura' ) === false && ! in_array( $hook_suffix, [ 'profile.php', 'user-edit.php' ], true ) ) {
            return;
        }

        // ALWAYS remove standard WordPress notices from Nexura pages
        if ( strpos( $hook_suffix, 'nexura' ) !== false ) {
            remove_all_actions( 'admin_notices' );
            remove_all_actions( 'all_admin_notices' );
            add_action( 'admin_notices', 'settings_errors' );
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
                
                $human_count = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}NEXURA_recaptcha_logs WHERE DATE(timestamp) = %s AND score >= %f", $date, $threshold ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                $bot_count   = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}NEXURA_recaptcha_logs WHERE DATE(timestamp) = %s AND score < %f", $date, $threshold ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                
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
                'nexura-performance', 'nexura-file-snapshots', 'nexura-logs',
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

        // If Pro plugin is active and has its own view registered via add_submenu_page,
        // skip the Free version's view to prevent double rendering.
        if ( 'security-headers' === $view && nexura_is_pro() ) {
            return;
        }

        if ( file_exists( $file ) ) {
            require NEXURA_PLUGIN_DIR . 'admin/views/partials/header.php';
            require $file;
            require NEXURA_PLUGIN_DIR . 'admin/views/partials/footer.php';
        } else {
            echo '<div class="notice notice-error"><p>View not found: ' . esc_html( $view ) . '</p></div>';
        }
    }

    /**
     * Registers the WordPress dashboard widget.
     */
    public function register_dashboard_widget() {
        wp_add_dashboard_widget(
            'nexura_dashboard_widget',
            __( 'Nexura Security Status', 'nexura-security' ),
            [ $this, 'render_dashboard_widget' ]
        );
    }

    /**
     * Renders the content of the dashboard widget.
     */
    /**
     * Renders the content of the dashboard widget.
     */
    public function render_dashboard_widget() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'NEXURA_scan_results';
        
        $total_issues = 0;
        $high_issues = 0;
        $medium_issues = 0;
        $critical_issues = 0;
        $scanned_files = (int) get_option( 'NEXURA_scan_total', 0 );
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        if ( $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table_name ) ) === $table_name ) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $total_issues = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table_name}" );
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $high_issues = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table_name} WHERE risk_score = %s", 'High' ) );
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $medium_issues = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table_name} WHERE risk_score = %s", 'Medium' ) );
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $critical_issues = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table_name} WHERE risk_score = %s", 'Critical' ) );
        }
        
        $score = 100;
        if ( $critical_issues > 0 ) $score -= min( 80, $critical_issues * 30 );
        if ( $high_issues > 0 )     $score -= min( 50, $high_issues * 15 );
        if ( $medium_issues > 0 )   $score -= min( 30, $medium_issues * 5 );
        if ( $total_issues > 0 && $score >= 80 ) {
            $score = 79;
        }
        $score = max( 0, $score );
        
        // Match WP native site health colors
        $score_color = $score >= 80 ? '#00a32a' : ( $score >= 50 ? '#dba617' : '#d63638' );
        $score_label = $score >= 80 ? __( 'Protected', 'nexura-security' ) : ( $score >= 50 ? __( 'Should be improved', 'nexura-security' ) : __( 'At Risk', 'nexura-security' ) );

        $dasharray = 565.48;
        $dashoffset = $dasharray - ( $score / 100 ) * $dasharray;
        
        $icon_url = NEXURA_PLUGIN_URL . 'admin/img/icon.png';
        
        ?>
        <div class="health-stat" style="display: flex; gap: 20px; align-items: center; margin-top: 10px; padding-bottom: 20px; border-bottom: 1px solid #ccd0d4;">
            <div class="site-health-progress-wrapper" style="text-align: center; width: 30%; flex-shrink: 0;">
                <div class="site-health-progress" style="width: 70px; height: 70px; margin: 0 auto 10px; position: relative;">
                    <svg width="70" height="70" viewBox="0 0 200 200" version="1.1" xmlns="http://www.w3.org/2000/svg" style="transform: rotate(-90deg);">
                        <circle r="90" cx="100" cy="100" fill="transparent" stroke="#f0f0f1" stroke-width="15" stroke-dasharray="565.48" style="stroke-dashoffset: 0; stroke: #f0f0f1;"></circle>
                        <circle r="90" cx="100" cy="100" fill="transparent" stroke-width="15" stroke-dasharray="565.48" style="stroke: <?php echo esc_attr( $score_color ); ?> !important; stroke-dashoffset: <?php echo esc_attr( $dashoffset ); ?>px !important; transition: stroke-dashoffset 1s ease-in-out;"></circle>
                    </svg>
                </div>
                <div class="site-health-progress-label" style="font-weight: 600; color: #1e1e1e; font-size: 14px;">
                    <?php echo esc_html( $score_label ); ?>
                </div>
                <div style="margin-top: 8px;">
                    <img src="<?php echo esc_url( $icon_url ); ?>" alt="Nexura Security" style="width: 24px; height: 24px; border-radius: 4px; vertical-align: middle;">
                </div>
            </div>

            <div class="site-health-details" style="flex: 1;">
                <?php if ( $total_issues > 0 ) : ?>
                    <p style="margin-top: 0; font-size: 14px; color: #3c434a;">
                        <?php esc_html_e( 'Your site has critical security issues that should be addressed as soon as possible to improve its protection.', 'nexura-security' ); ?>
                    </p>
                    <p style="font-size: 14px; color: #3c434a;">
                        <?php 
                        printf(
                            /* translators: 1: Number of issues, 2: URL to Nexura Security screen */
                            wp_kses_post( __( 'Take a look at the <strong>%1$d issues</strong> on the <a href="%2$s">Nexura Security</a> screen.', 'nexura-security' ) ),
                            (int) $total_issues,
                            esc_url( admin_url( 'admin.php?page=nexura-issues-detected' ) )
                        );
                        ?>
                    </p>
                <?php else : ?>
                    <p style="margin-top: 0; font-size: 14px; color: #3c434a;">
                        <?php esc_html_e( 'Your site’s security is looking good. Nexura Security is actively monitoring your website to keep it safe.', 'nexura-security' ); ?>
                    </p>
                    <p style="font-size: 14px; color: #3c434a;">
                        <?php 
                        printf(
                            /* translators: 1: Number of files scanned, 2: URL to Nexura Security screen */
                            wp_kses_post( __( 'You have <strong>%1$s files scanned</strong> on the <a href="%2$s">Nexura Security</a> screen.', 'nexura-security' ) ),
                            esc_html( number_format_i18n( $scanned_files ) ),
                            esc_url( admin_url( 'admin.php?page=nexura' ) )
                        );
                        ?>
                    </p>
                <?php endif; ?>
            </div>
        </div>

        <ul style="margin: 15px 0 0 0; padding: 0; list-style: none;">
            <li style="display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #f0f0f1;">
                <span style="color: #646970; font-weight: 500;"><span class="dashicons dashicons-shield" style="font-size: 16px; width: 16px; height: 16px; line-height: 16px; vertical-align: text-top; margin-right: 5px;"></span> <?php esc_html_e( 'Security Score', 'nexura-security' ); ?></span>
                <?php $list_score_color = $score >= 80 ? '#10b981' : ( $score >= 50 ? '#f59e0b' : '#ef4444' ); ?>
                <span style="font-weight: 600; color: <?php echo esc_attr( $list_score_color ); ?>;"><?php echo esc_html( $score ); ?>/100</span>
            </li>
            
            <li style="display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #f0f0f1;">
                <span style="color: #646970; font-weight: 500;"><span class="dashicons dashicons-bell" style="font-size: 16px; width: 16px; height: 16px; line-height: 16px; vertical-align: text-top; margin-right: 5px;"></span> <?php esc_html_e( 'Notifications', 'nexura-security' ); ?></span>
                <span style="font-weight: 600;"><?php echo $total_issues > 0 ? '<span style="background: #ef4444; color: #fff; padding: 2px 8px; border-radius: 12px; font-size: 11px;">' . esc_html( $total_issues ) . '</span>' : '0'; ?></span>
            </li>
            
            <li style="display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #f0f0f1;">
                <span style="color: #646970; font-weight: 500;"><span class="dashicons dashicons-warning" style="font-size: 16px; width: 16px; height: 16px; line-height: 16px; vertical-align: text-top; margin-right: 5px;"></span> <?php esc_html_e( 'High Risk Threats', 'nexura-security' ); ?></span>
                <?php $high_color = $high_issues > 0 ? '#ef4444' : '#10b981'; ?>
                <span style="font-weight: 600; color: <?php echo esc_attr( $high_color ); ?>;"><?php echo esc_html( $high_issues ); ?></span>
            </li>
            
            <li style="display: flex; justify-content: space-between; padding: 8px 0;">
                <span style="color: #646970; font-weight: 500;"><span class="dashicons dashicons-analytics" style="font-size: 16px; width: 16px; height: 16px; line-height: 16px; vertical-align: text-top; margin-right: 5px;"></span> <?php esc_html_e( 'File Integrity Overview', 'nexura-security' ); ?></span>
                <span style="font-weight: 600; color: #10b981;"><?php esc_html_e( 'Monitoring Active', 'nexura-security' ); ?></span>
            </li>
        </ul>
        <?php
    }

    /**
     * Renders Nexura Security marketing box at the top of the Publish meta box.
     */
    public function render_post_submitbox_marketing( $post ) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'NEXURA_scan_results';
        $total_issues = 0;
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        if ( $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table_name ) ) === $table_name ) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $total_issues = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table_name}" );
        }

        $icon_url = NEXURA_PLUGIN_URL . 'admin/img/icon.png';
        
        $health_color = $total_issues > 0 ? '#ef4444' : '#10b981';
        $health_text  = $total_issues > 0 ? __( 'Page Health: At Risk', 'nexura-security' ) : __( 'Page Health: Excellent', 'nexura-security' );
        $health_icon  = $total_issues > 0 ? 'dashicons-warning' : 'dashicons-shield';
        $bg_color     = $total_issues > 0 ? '#fef2f2' : '#f0f6fc';
        ?>
        <div style="width: 100%;padding: 10px; margin-bottom: 10px; border-bottom: 1px solid #dcdcde; display: flex; align-items: center; gap: 10px; background: <?php echo esc_attr( $bg_color ); ?>; border-radius: 4px;">
            <img src="<?php echo esc_url( $icon_url ); ?>" alt="Nexura Security" style="width: 24px; height: 24px; border-radius: 4px;">
            <div style="font-size: 12px; line-height: 1.4;">
                <strong style="color: #1e1e1e; display: block; font-size: 13px;"><?php esc_html_e( 'Protected by Nexura', 'nexura-security' ); ?></strong>
                <span style="color: <?php echo esc_attr( $health_color ); ?>; font-weight: 500; font-size: 12px;"><span class="dashicons <?php echo esc_attr( $health_icon ); ?>" style="font-size: 14px; width: 14px; height: 14px; line-height: 14px; vertical-align: text-top;"></span> <?php echo esc_html( $health_text ); ?></span>
            </div>
        </div>
        <?php
    }

    /**
     * Adds Nexura Security notification badge to the WP Admin Bar.
     */
    public function add_admin_bar_notification( $wp_admin_bar ) {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'NEXURA_scan_results';
        $issues_count = 0;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        if ( $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table_name ) ) === $table_name ) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $issues_count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table_name}" );
        }

        $icon_url = NEXURA_PLUGIN_URL . 'admin/img/icon.png';
        $title = '<span class="ab-icon"><img src="' . esc_url( $icon_url ) . '" alt="Nexura" style="width: 20px; height: 20px; border-radius: 3px; margin-top: 6px;"></span>';
        $title .= '<span class="ab-label">Nexura</span>';
        
        if ( $issues_count > 0 ) {
            $title .= ' <span class="update-plugins count-' . esc_attr( $issues_count ) . '" style="background-color: #d63638; color: #fff; border-radius: 10px; padding: 0 6px; font-weight: 600; font-size: 11px; margin-left: 5px;"><span class="plugin-count">' . esc_html( $issues_count ) . '</span></span>';
        } else {
            $title .= ' <span class="update-plugins count-0" style="background-color: #00a32a; color: #fff; border-radius: 10px; padding: 0 6px; font-weight: 600; font-size: 11px; margin-left: 5px;"><span class="plugin-count">&#10003;</span></span>';
        }

        $wp_admin_bar->add_node( [
            'id'    => 'nexura-security',
            'title' => $title,
            'href'  => admin_url( 'admin.php?page=nexura' ),
            'meta'  => [
                'title' => __( 'Nexura Security Dashboard', 'nexura-security' ),
            ],
        ] );

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

        foreach ( $submenu_pages as $slug => $page_title ) {
            $wp_admin_bar->add_node( [
                'id'     => 'nexura-bar-' . $slug,
                'parent' => 'nexura-security',
                'title'  => $page_title,
                'href'   => admin_url( 'admin.php?page=nexura-' . $slug ),
            ] );
        }
    }

}
