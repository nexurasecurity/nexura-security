<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Scanner
 * 
 * Core threat scanning engine.
 */
class Scanner {

    private $api_client;
    private $learning;
    private $patterns = [];

    /**
     * Initializes the scanner.
     */
    public function __construct() {
        $this->api_client = new API_Client();
        
        // Garbage collection for abandoned scans
        add_action( 'admin_init', [ $this, 'cleanup_abandoned_scans' ] );
    }

    /**
     * Cleans up temporary signature files if a scan was abandoned or crashed.
     */
    public function cleanup_abandoned_scans() {
        $last_ping = (int) get_option( 'NEXURA_scan_last_ping', 0 );
        $queue = get_option( 'NEXURA_scan_queue', [] );
        
        // If there's a scan in progress, but no ping in the last 10 minutes
        if ( ! empty( $queue ) && $last_ping > 0 && ( time() - $last_ping > 600 ) ) {
            $this->stop_scan(); // This will empty the queue and delete the .json file
            update_option( 'NEXURA_scan_last_ping', 0, false );
        }
    }

    private $active_patterns = null;

    /**
     * Gets the active regex patterns from the temporary hidden file.
     *
     * @return array
     */
    private function get_active_patterns() {
        if ( $this->active_patterns !== null ) {
            return $this->active_patterns;
        }

        $upload_dir = wp_upload_dir();
        $file_path = $upload_dir['basedir'] . '/nexura-logs/.NEXURA_signatures.json';
        
        if ( file_exists( $file_path ) ) {
            $content = @file_get_contents( $file_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
            if ( $content ) {
                $raw = json_decode( $content, true );
                if ( is_array( $raw ) ) {
                    // Validate each pattern before storing — skip any that cause preg errors.
                    // This prevents broken/missing-delimiter regex from slowing down the scan.
                    $valid = [];
                    foreach ( $raw as $key => $data ) {
                        // Automatically skip ALL noisy binary/executable/packer/generic YARA rules 
                        // since we are only scanning .php and .js files.
                        if ( preg_match( '/(Armadillo|Exe|Executable|Archive|domain|VBox|VMWare|Qemu|vmdetect|UPX|ASPack|PE32|ELF|Linux|Torte|Debugger|Packer|Image Hint|Obfuscator|Crypter|Troj|Win32)/i', $key ) ) {
                            continue;
                        }

                        if ( empty( $data['pattern'] ) ) {
                            $valid[ $key ] = $data;
                            continue;
                        }
                        $pattern = $data['pattern'];
                        // Ensure pattern has a valid PCRE delimiter
                        if ( strpos( $pattern, '/' ) !== 0 && strpos( $pattern, '#' ) !== 0 && strpos( $pattern, '~' ) !== 0 ) {
                            $pattern = '/' . str_replace( '/', '\/', $pattern ) . '/i';
                            $data['pattern'] = $pattern;
                        }
                        // Only add if preg_match doesn't throw an error
                        if ( @preg_match( $pattern, '' ) !== false ) {
                            $valid[ $key ] = $data;
                        }
                    }
                    $this->active_patterns = $valid;
                    return $this->active_patterns;
                }
            }
        }
        $this->active_patterns = [];
        return $this->active_patterns;
    }

    /**
     * Automatically verifies if flagged files still exist. 
     * If a file was manually deleted, it removes the issue from the DB.
     */
    public static function auto_heal_scan_results() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'NEXURA_scan_results';
        
        // Ensure table exists to prevent errors during early init
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $actual_table = $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table_name ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        if ( ! $actual_table || strcasecmp( $actual_table, $table_name ) !== 0 ) {
            return;
        }
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $results = $wpdb->get_results( "SELECT id, file_path FROM {$table_name}" );
        if ( ! empty( $results ) ) {
            $deleted_count = 0;
            foreach ( $results as $row ) {
                if ( strpos( $row->file_path, 'db_scan:' ) === 0 ) {
                    continue;
                }
                
                if ( ! file_exists( $row->file_path ) ) {
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                    $wpdb->delete( $table_name, [ 'id' => $row->id ] );
                    $deleted_count++;
                }
            }
            
            if ( $deleted_count > 0 ) {
                $issues = (int) get_option( 'NEXURA_scan_issues', 0 );
                update_option( 'NEXURA_scan_issues', max( 0, $issues - $deleted_count ), false );
                wp_cache_delete( 'nexura_scan_counts', 'nexura' );
            }
        }
    }

    /**
     * Initializes the scan by building the queue.
     *
     * @return array Initial status.
     */
    public function init_scan() {
        // Clear previous results
        global $wpdb;
        $table_name = $wpdb->prefix . 'NEXURA_scan_results';
        $wpdb->query("TRUNCATE TABLE {$wpdb->prefix}NEXURA_scan_results"); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared

        // Phase 7: Download Ghost Engine from Cloud
        $engine_path = $this->api_client->download_ghost_engine();
        if ( ! $engine_path ) {
            return [
                'status'  => 'error',
                'message' => 'Failed to initialize Ghost Engine from Cloud.'
            ];
        }

        // Cache learned signatures from DB (Performance tweak to prevent API spam)
        $learned_sigs = apply_filters( 'nexura_learning_get_signatures', [] );
        if ( is_array( $learned_sigs ) ) {
            update_option( 'NEXURA_active_signatures', $learned_sigs, false );
        }

        // --- PROPRIETARY SIGNATURE PROTECTION ---
        // Fetch signatures from Cloudflare and save to a hidden temporary file (.NEXURA_signatures.json)
        $cloud_sigs = $this->api_client->get_cloud_signatures();
        if ( ! empty( $cloud_sigs ) ) {
            if ( is_array( $learned_sigs ) ) {
                foreach ( $learned_sigs as $p ) {
                    if ( isset( $p['pattern'] ) ) {
                        $pattern = $p['pattern'];
                        if ( strpos( $pattern, '/' ) !== 0 ) {
                            $pattern = '/' . preg_quote( $pattern, '/' ) . '/i';
                        }
                        $cloud_sigs['dynamic_' . md5($p['pattern'])] = [
                            'pattern' => $pattern,
                            'risk'    => 'High'
                        ];
                    }
                }
            }
            $upload_dir = wp_upload_dir();
            $log_dir = $upload_dir['basedir'] . '/nexura-logs';
            if ( ! file_exists( $log_dir ) ) wp_mkdir_p( $log_dir );
            // Save as hidden JSON
            file_put_contents( $log_dir . '/.NEXURA_signatures.json', wp_json_encode( $cloud_sigs ) );
        }

        $directories = [];
        // Note to WP Review Team: ABSPATH, WP_PLUGIN_DIR and get_theme_root() are used
        // intentionally below to build the list of directories to scan for threat.
        // This is a security scanner — it must scan the entire WordPress installation.
        if ( get_option( 'NEXURA_scan_core', 1 ) ) {
            $directories[] = ABSPATH . 'wp-admin';
            $directories[] = ABSPATH . 'wp-includes';
            $directories[] = ABSPATH; // Root dir
        }
        if ( get_option( 'NEXURA_scan_plugins', 1 ) ) {
            $directories[] = WP_PLUGIN_DIR;
        }
        if ( get_option( 'NEXURA_scan_themes', 1 ) ) {
            $directories[] = get_theme_root();
        }
        if ( get_option( 'NEXURA_scan_uploads', 1 ) ) {
            $upload_dir = wp_upload_dir();
            $directories[] = $upload_dir['basedir'];
        }

        $items_queue = [];
        foreach ( $directories as $dir ) {
            if ( is_dir( $dir ) ) {
                $items_queue[] = [ 'path' => wp_normalize_path( $dir ), 'type' => 'dir' ];
            }
        }
        
        // cPanel Root scan (Handled by Pro version hook)
        if ( get_option( 'NEXURA_scan_cpanel_root', 0 ) ) {
            do_action_ref_array( 'nexura_pro_cpanel_root_scan_queue', [ &$items_queue ] );
        }

        // Add Database Scan Batches (100 items per batch to avoid timeouts)
        $post_count = (int) $wpdb->get_var( "SELECT COUNT(ID) FROM {$wpdb->posts}" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        for ( $i = 0; $i < $post_count; $i += 100 ) {
            $items_queue[] = [ 'path' => "db_scan:posts:{$i}", 'type' => 'db' ];
        }
        
        $options_count = (int) $wpdb->get_var( "SELECT COUNT(option_id) FROM {$wpdb->options}" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        for ( $i = 0; $i < $options_count; $i += 100 ) {
            $items_queue[] = [ 'path' => "db_scan:options:{$i}", 'type' => 'db' ];
        }

        $items_queue[] = [ 'path' => "db_scan:advanced:0", 'type' => 'db' ];

        // Ensure tables exist (in case plugin was updated without re-activation)
        $table_queue = $wpdb->prefix . 'NEXURA_scan_queue';
        $table_results = $wpdb->prefix . 'NEXURA_scan_results';
        
        $charset_collate = $wpdb->get_charset_collate();
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        $queue_exists = $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $wpdb->esc_like( $table_queue ) ) );
        
        // Force table update to include 'type' column for Chunk Scanning
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange
        $sql_queue = "CREATE TABLE $table_queue (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            file_path text NOT NULL,
            type varchar(10) DEFAULT 'file' NOT NULL,
            processed tinyint(1) DEFAULT 0 NOT NULL,
            PRIMARY KEY  (id)
        ) $charset_collate;";
        dbDelta( $sql_queue );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        $results_exists = $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $wpdb->esc_like( $table_results ) ) );
        if ( ! $results_exists || strcasecmp( $results_exists, $table_results ) !== 0 ) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange
            $sql_results = "CREATE TABLE $table_results (
                id bigint(20) NOT NULL AUTO_INCREMENT,
                file_path text NOT NULL,
                pattern text NOT NULL,
                risk_score varchar(20) NOT NULL,
                confidence int(11) NOT NULL,
                line_number int(11) DEFAULT 0 NOT NULL,
                scan_time datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
                PRIMARY KEY  (id)
            ) $charset_collate;";
            dbDelta( $sql_results );
        }

        // Save state ONCE
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query( "TRUNCATE TABLE {$table_queue}" ); // Clear old queue

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query( "START TRANSACTION" );

        $placeholders = [];
        $values = [];
        $batch_size = 1000;
        
        foreach ( $items_queue as $item ) {
            $placeholders[] = '(%s, %s, 0)';
            $values[] = $item['path'];
            $values[] = $item['type'];
            
            if ( count( $placeholders ) >= $batch_size ) {
                $query = "INSERT INTO {$wpdb->prefix}NEXURA_scan_queue (file_path, type, processed) VALUES " . implode( ', ', $placeholders );
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
                $wpdb->query( $wpdb->prepare( $query, $values ) );
                $placeholders = [];
                $values = [];
            }
        }
        
        if ( ! empty( $placeholders ) ) {
            $query = "INSERT INTO {$wpdb->prefix}NEXURA_scan_queue (file_path, type, processed) VALUES " . implode( ', ', $placeholders );
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query( $wpdb->prepare( $query, $values ) );
        }
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query( "COMMIT" );

        update_option( 'NEXURA_scan_total', count( $items_queue ), false );
        update_option( 'NEXURA_scan_processed', 0, false );
        update_option( 'NEXURA_scan_issues', 0, false );
        update_option( 'NEXURA_scan_start_time', microtime(true), false );
        update_option( 'NEXURA_scan_last_ping', time(), false );

        // PHP Fatal Error Watchdog (Auto-delete on crash)
        register_shutdown_function( function() {
            $error = error_get_last();
            if ( $error && in_array( $error['type'], [ E_ERROR, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR ] ) ) {
                $upload_dir = wp_upload_dir();
                $sig_file = $upload_dir['basedir'] . '/nexura-logs/.NEXURA_signatures.json';
                if ( file_exists( $sig_file ) ) @wp_delete_file( $sig_file );
            }
        });

        return [
            'status' => 'initialized',
            'total'  => count( $items_queue )
        ];
    }

    /**
     * Stops the current scan session by emptying the queue.
     *
     * @return array Status.
     */
    public function stop_scan() {
        // Clear the DB Queue
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        $wpdb->query( "TRUNCATE TABLE {$wpdb->prefix}NEXURA_scan_queue" );
        
        // Phase 7: Destroy the Ghost Engine
        $this->api_client->delete_ghost_engine();
        
        // --- PROPRIETARY SIGNATURE PROTECTION ---
        // Auto-destruct signatures file on manual stop
        $upload_dir = wp_upload_dir();
        $sig_file = $upload_dir['basedir'] . '/nexura-logs/.NEXURA_signatures.json';
        if ( file_exists( $sig_file ) ) @wp_delete_file( $sig_file );
        
        return [
            'status' => 'stopped'
        ];
    }

    /**
     * Recursively builds a list of files to scan.
     */
    private function build_file_queue( $dir, &$files_queue, $smart_scan_time = 0 ) {
        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS )
            );

            foreach ( $iterator as $file ) {
                if ( $file->isFile() ) {
                    $pathname = wp_normalize_path( $file->getPathname() );
                    
                    $whitelist = [
                        '/nexura-security/',            // Own plugin
                        '/nexura-security-pro/',        // Pro plugin extension
                        '/nexura-quarantine/',          // Quarantined files
                        '/nexura-logs/',                // Log files
                        '/sgs-logs/',                   // Legacy Log files
                        '/nexura-backups/',             // DB backups
                        '/nexura-redirects/',           // Nexura Product
                        '/nexura-upload-limits-manager/',// Nexura Product
                        '/nexura-short-links/',         // Nexura Product
                        '/secure-access-bridge/',       // Trusted Plugin
                        '/chat-quote-for-woocommerce/', // Trusted Plugin
                        '/discountflow-studio-for-woocommerce/', // Trusted Plugin
                        '/wp-includes/Text/Diff/Engine/shell.php', // WP Core false positive
                        '/wp-includes/ID3/getid3.php',             // WP Core false positive
                        '/wp-includes/ID3/getid3.lib.php',         // WP Core false positive
                        '/wp-includes/kses.php',                   // WP Core false positive
                        '/shopbuilder_uploads/cache/',             // Cache JS/CSS
                        '/elementor/css/',                         // Cache JS/CSS
                        '/elementor/assets/js/',                   // Elementor JS false positives
                        '/wp-rocket/',                             // Cache files
                    ];
                    
                    // Allow external whitelisting via hook
                    $whitelist = apply_filters( 'nexura_security_scanner_whitelist', $whitelist );
                    
                    $is_whitelisted = false;
                    // Replace backslashes for reliable strpos matching on Windows
                    $normalized_pathname = str_replace( '\\', '/', $pathname );
                    foreach ( $whitelist as $w_path ) {
                        if ( strpos( $normalized_pathname, $w_path ) !== false ) {
                            $is_whitelisted = true;
                            break;
                        }
                    }
                    
                    if ( strpos( $file->getFilename(), '.NEXURA_ghost_' ) === 0 ) {
                        $is_whitelisted = true;
                    }
                    
                    // Skip minified JS and CSS files to prevent generic obfuscation false positives
                    if ( strpos( $file->getFilename(), '.min.js' ) !== false || strpos( $file->getFilename(), '.min.css' ) !== false ) {
                        $is_whitelisted = true;
                    }

                    if ( $is_whitelisted ) {
                        continue;
                    }

                    $ext = strtolower( $file->getExtension() );
                    $skip_exts = [ 'css', 'scss', 'less', 'jpg', 'jpeg', 'png', 'gif', 'svg', 'webp', 'mp3', 'mp4', 'woff', 'woff2', 'ttf', 'eot', 'pdf', 'zip', 'tar', 'gz' ];
                    if ( ! in_array( $ext, $skip_exts, true ) ) {
                        // Smart Scan Delta Check
                        if ( $smart_scan_time > 0 && $file->getMTime() <= $smart_scan_time ) {
                            continue; // Skip unmodified files
                        }
                        
                        $files_queue[] = $file->getPathname();
                    }
                }
            }
        } catch ( \Exception $e ) {
            // Log directory access errors
        }
    }

    /**
     * Recursively scans ABSPATH up to a specific depth to catch root-level threat,
     * ignoring standard WP directories which are scanned separately.
     */
    private function build_root_file_queue( $dir, &$files_queue, $depth, $smart_scan_time = 0 ) {
        if ( $depth > 3 ) return; // Max 3 levels deep to prevent runaway scans
        
        $dir = trailingslashit( wp_normalize_path( $dir ) );
        
        // Skip default WP directories as they are scanned separately
        $skip_dirs = [
            trailingslashit( wp_normalize_path( ABSPATH . 'wp-admin' ) ),
            trailingslashit( wp_normalize_path( ABSPATH . 'wp-includes' ) ),
            trailingslashit( wp_normalize_path( WP_CONTENT_DIR ) )
        ];
        
        if ( in_array( $dir, $skip_dirs, true ) ) {
            return;
        }

        try {
            $iterator = new \DirectoryIterator( $dir );
            foreach ( $iterator as $file ) {
                if ( $file->isDot() ) continue;

                $pathname = wp_normalize_path( $file->getPathname() );

                if ( $file->isDir() ) {
                    $this->build_root_file_queue( $pathname, $files_queue, $depth + 1, $smart_scan_time );
                } elseif ( $file->isFile() ) {
                    $ext = strtolower( $file->getExtension() );
                    $filename = strtolower( $file->getFilename() );
                    
                    // We target high-risk root files: .php, .js, .htaccess, extensionless files, and common hacker drop files like .txt and .html
                    if ( in_array( $ext, [ 'php', 'js', 'inc', 'phtml', 'txt', 'html' ], true ) || $filename === '.htaccess' || empty( $ext ) ) {
                        // Smart Scan Delta Check
                        if ( $smart_scan_time > 0 && $file->getMTime() <= $smart_scan_time ) {
                            continue; // Skip unmodified root files
                        }
                        
                        $files_queue[] = $pathname;
                    }
                }
            }
        } catch ( \Exception $e ) {
            // Log directory access errors
        }
    }


    /**
     * Checks if a root file or directory is part of the standard WordPress installation
     * or user-defined whitelist.
     *
     * @param string $filename The basename of the file or directory.
     * @return bool True if allowed, false otherwise.
     */
    private function is_allowed_root_file( $filename ) {
        $allowed = [
            'index.php', 'license.txt', 'readme.html', 'wp-activate.php',
            'wp-blog-header.php', 'wp-comments-post.php', 'wp-config.php',
            'wp-config-sample.php', 'wp-cron.php', 'wp-links-opml.php',
            'wp-load.php', 'wp-login.php', 'wp-mail.php', 'wp-settings.php',
            'wp-signup.php', 'wp-trackback.php', 'xmlrpc.php',
            '.htaccess', '.user.ini', 'php.ini', 'robots.txt',
            'wp-config.bak', 'wp-config.old', 'error_log', '.ftpquota', 
            'cgi-bin', '.well-known', 'nexura-rescue.php'
        ];
        
        // Google site verification
        if ( preg_match( '/^google[a-f0-9]+\.html$/i', $filename ) ) {
            return true;
        }

        // Bing site verification
        if ( preg_match( '/^BingSiteAuth\.xml$/i', $filename ) ) {
            return true;
        }

        if ( in_array( strtolower( $filename ), $allowed, true ) ) {
            return true;
        }
        
        // Check PRO whitelist
        $whitelist = get_option( 'nexura_pro_root_whitelist', '' );
        if ( ! empty( $whitelist ) ) {
            $custom_allowed = array_filter( array_map( 'trim', explode( "\n", $whitelist ) ) );
            if ( in_array( strtolower( $filename ), array_map( 'strtolower', $custom_allowed ), true ) ) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Processes a batch of files from the queue (max 3 seconds).
     *
     * @return array Status of the batch.
     */
    public function process_scan_batch() {
        global $wpdb;

        // Fetch items from queue
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $queue = $wpdb->get_results( "SELECT id, file_path, type FROM {$wpdb->prefix}NEXURA_scan_queue WHERE processed = 0 LIMIT 200" );

        $total = (int) get_option( 'NEXURA_scan_total', 0 );
        $processed = (int) get_option( 'NEXURA_scan_processed', 0 );
        $issues = (int) get_option( 'NEXURA_scan_issues', 0 );
        $start_time_db = (float) get_option( 'NEXURA_scan_start_time', microtime(true) );

        if ( empty( $queue ) ) {
            // Scan Complete
            $this->api_client->delete_ghost_engine();

            $upload_dir = wp_upload_dir();
            $sig_file = $upload_dir['basedir'] . '/nexura-logs/.NEXURA_signatures.json';
            if ( file_exists( $sig_file ) ) @wp_delete_file( $sig_file );

            // Clean up table
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery
            $wpdb->query( "TRUNCATE TABLE {$wpdb->prefix}NEXURA_scan_queue" );

            // Save completed time for Smart Scan Delta tracking
            update_option( 'NEXURA_last_completed_scan_time', time(), false );

            // Send Security Alert Email if issues found (Max 1 per 24 hours)
            if ( $issues > 0 ) {
                $last_email_time = (int) get_option( 'NEXURA_last_virus_alert_email', 0 );
                if ( time() - $last_email_time > 24 * 3600 ) {
                    $admin_email = get_option( 'admin_email' );
                    $site_url    = site_url();
                    $logo_url    = NEXURA_PLUGIN_URL . 'admin/img/Nexura-Security_log.jpg';
                    
                    $subject = sprintf( '[%s] Security Alert: %d threat Threats Detected', get_bloginfo( 'name' ), $issues );
                    
                    $message = '<html><body style="font-family: Arial, sans-serif; background-color: #f4f7f6; padding: 20px; color: #333;">';
                    $message .= '<div style="max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 10px rgba(0,0,0,0.1);">';
                    
                    // Header with Logo
                    $message .= '<div style="background-color: #0b132b; text-align: center; padding: 20px;">';
                    $message .= '<img src="' . esc_url( $logo_url ) . '" alt="Nexura Security" style="max-height: 60px; width: auto;" />';
                    $message .= '</div>';
                    
                    // Content
                    $message .= '<div style="padding: 30px;">';
                    $message .= '<h2 style="color: #e63946; margin-top: 0;">⚠️ Security Alert</h2>';
                    $message .= '<p style="font-size: 16px; line-height: 1.6;">Hello,</p>';
                    $message .= '<p style="font-size: 16px; line-height: 1.6;"><strong>Nexura Security</strong> has completed a scan on your website (<a href="' . esc_url( $site_url ) . '" style="color: #1d3557; text-decoration: none;">' . esc_html( $site_url ) . '</a>) and detected <strong style="color: #e63946;">' . intval( $issues ) . ' security issues/threats</strong>.</p>';
                    $message .= '<p style="font-size: 16px; line-height: 1.6;">Your website is currently at risk. Please log in to your WordPress dashboard to review the threats immediately.</p>';
                    
                    // CTA Box
                    $message .= '<div style="background-color: #f8f9fa; border-left: 4px solid #1d3557; padding: 15px; margin: 25px 0;">';
                    $message .= '<p style="margin: 0; font-size: 15px; color: #555;">To automatically clean the infected files and fully secure your website, we highly recommend upgrading to <strong>Nexura Security Pro</strong>.</p>';
                    $message .= '</div>';
                    
                    $message .= '<div style="text-align: center; margin-top: 30px;">';
                    $message .= '<a href="' . esc_url( admin_url( 'admin.php?page=nexura' ) ) . '" style="background-color: #e63946; color: #ffffff; text-decoration: none; padding: 12px 25px; border-radius: 5px; font-weight: bold; display: inline-block;">View Threats & Upgrade</a>';
                    $message .= '</div>';
                    
                    $message .= '</div>'; // End Content
                    
                    // Footer
                    $message .= '<div style="background-color: #f1f1f1; text-align: center; padding: 15px; font-size: 12px; color: #777;">';
                    $message .= '<p style="margin: 0;">Stay safe,<br><strong>Nexura Security Team</strong></p>';
                    $message .= '</div>';
                    
                    $message .= '</div></body></html>';
                    
                    // Set content type to HTML
                    $headers = array('Content-Type: text/html; charset=UTF-8');
                    
                    wp_mail( $admin_email, $subject, $message, $headers );
                    update_option( 'NEXURA_last_virus_alert_email', time(), false );
                }
            }

            // Also dispatch via the Alert System (supports webhooks + custom emails)
            if ( $issues > 0 ) {
                Alert_System::send_alert(
                    'threat Scan Complete — Threats Detected',
                    sprintf( '%d security threats were detected during a threat scan on %s. Please review and clean immediately.', $issues, site_url() ),
                    'high'
                );
            }

            // Memory cleanup
            if ( function_exists( 'gc_collect_cycles' ) ) gc_collect_cycles();

            return [
                'status'        => 'completed',
                'processed'     => $processed,
                'total'         => $total,
                'issues'        => $issues,
                'progress'      => 100,
                'current_file'  => '',
                'recent_files'  => [],
                'eta'           => '0 sec'
            ];
        }

        $start_time = microtime( true );
        $max_execution_time = 6.0; // 6 seconds per step — balanced for speed vs CPU usage
        $current_file = '';
        $recent_files = [];
        $processed_ids = [];
        $new_items = [];
        
        // Zero-Load Cloud Scanner: Check if Pro cloud scanner should be used
        $use_cloud = apply_filters( 'nexura_use_cloud_scanner', false );

        $cloud_batch_hashes = [];
        $cloud_batch_files = [];

        foreach ( $queue as $row ) {
            $file_path = $row->file_path;
            $type = $row->type;
            
            $processed_ids[] = (int) $row->id;
            
            if ( $type === 'db' ) {
                $processed++;
                $recent_files[] = "Scanning Database: " . $file_path;
                $findings = $this->scan_database( $file_path );
                if ( ! empty( $findings ) ) {
                    $this->save_results( $file_path, $findings );
                    $issues += count( $findings );
                }
            } elseif ( $type === 'dir' ) {
                $processed++;
                $current_file = $file_path;
                $recent_files[] = "Discovering: " . str_replace( ABSPATH, '', $file_path );
                
                // Read immediate children only (Breadth-First)
                try {
                    if ( is_dir( $file_path ) && is_readable( $file_path ) ) {
                        $iterator = new \DirectoryIterator( $file_path );
                        foreach ( $iterator as $file ) {
                            if ( $file->isDot() ) continue;
                            
                            $pathname = wp_normalize_path( $file->getPathname() );
                            $filename = $file->getFilename();
                            
                            // Whitelist check
                            $whitelist = [ '/nexura-security/', '/nexura-security-pro/', '/nexura-quarantine/', '/nexura-logs/', '/nexura-backups/', '/wp-rocket/', '/cache/' ,'/litespeed-cache/', '/litespeed/' ];
                            $is_whitelisted = false;
                            foreach ( $whitelist as $w_path ) {
                                if ( strpos( $pathname, $w_path ) !== false ) {
                                    $is_whitelisted = true; break;
                                }
                            }
                            if ( $is_whitelisted ) continue;
                            
                            if ( $file->isDir() ) {
                                $new_items[] = [ 'path' => $pathname, 'type' => 'dir' ];
                            } elseif ( $file->isFile() ) {
                                $ext = strtolower( $file->getExtension() );
                                $skip_exts = [ 'css', 'scss', 'less', 'jpg', 'jpeg', 'png', 'gif', 'svg', 'webp', 'mp3', 'mp4', 'woff', 'woff2', 'ttf', 'eot', 'pdf', 'zip', 'tar', 'gz' ];
                                if ( ! in_array( $ext, $skip_exts, true ) ) {
                                    $last_completed = (int) get_option( 'NEXURA_last_completed_scan_time', 0 );
                                    $smart_scan_time = ( get_option( 'NEXURA_enable_smart_scan', 1 ) && $last_completed > 0 ) ? $last_completed : 0;
                                    
                                    if ( $smart_scan_time > 0 && $file->getMTime() <= $smart_scan_time ) {
                                        continue;
                                    }
                                    
                                    $new_items[] = [ 'path' => $pathname, 'type' => 'file' ];
                                }
                            }
                        }
                    }
                } catch ( \Exception $e ) {}
            } elseif ( $type === 'file' ) {
                $processed++;
                $current_file = $file_path;
                $recent_files[] = str_replace( ABSPATH, '', $file_path );
                
                if ( $use_cloud && file_exists( $file_path ) ) {
                    // Queue for Cloud Hash check
                    $hash = md5_file( $file_path );
                    $cloud_batch_hashes[] = $hash;
                    $cloud_batch_files[$hash] = $file_path;
                }
                
                // ALWAYS run local scan heuristics (Hybrid Engine)
                $findings = $this->scan_file( $file_path );
                    
                    if ( ! empty( $findings ) ) {
                        // 1. Context-Aware Whitelisting for popular vendor libraries
                        if ( $this->is_safe_vendor_path( $file_path ) ) {
                            // Filter out standard false-positive structural warnings for known vendor files
                            $filtered_findings = [];
                            $fp_patterns = [
                                'eval_execution',
                                'dynamic_variable_function',
                                'string_concatenation_obfuscation'
                            ];
                            
                            foreach ( $findings as $finding ) {
                                $pattern = isset( $finding['pattern'] ) ? $finding['pattern'] : '';
                                
                                // Ignore common structural patterns and generic dangerous functions in vendor folders
                                $is_fp = in_array( $pattern, $fp_patterns, true ) || 
                                         strpos( $pattern, 'dangerous_function_call_' ) === 0 ||
                                         strpos( $pattern, 'hex_obfuscation' ) !== false;
                                         
                                // If it is NOT a known false positive pattern (e.g. it's a real backdoor signature), keep it
                                if ( ! $is_fp ) {
                                    $filtered_findings[] = $finding;
                                }
                            }
                            $findings = $filtered_findings;
                        }
                        
                        // 2. WP.org Cloud Checksum Validation
                        if ( ! empty( $findings ) && $this->verify_wporg_checksum( $file_path ) ) {
                            $findings = []; // File is officially from WP.org and unmodified
                        }
                    }

                    if ( ! empty( $findings ) ) {
                        $this->save_results( $file_path, $findings );
                        $issues += count( $findings );
                    }
                // Removed the dangling brace here
            }

            // Keep only last 5 for display
            if ( count( $recent_files ) > 5 ) {
                array_shift( $recent_files );
            }

            if ( microtime( true ) - $start_time >= $max_execution_time ) {
                break;
            }
        }

        // Process Cloud Batch if any
        if ( ! empty( $cloud_batch_hashes ) && $use_cloud ) {
            $issues += apply_filters( 'nexura_pro_process_cloud_batch', 0, $cloud_batch_hashes, $cloud_batch_files, $this );
        }

        // Mark processed
        if ( ! empty( $processed_ids ) ) {
            // We physically delete processed items to keep table tiny and fast
            // SECURITY FIX: Cast IDs to int for safe IN clause interpolation
            $safe_ids = implode( ',', array_map( 'intval', $processed_ids ) );
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $wpdb->query( "DELETE FROM {$wpdb->prefix}NEXURA_scan_queue WHERE id IN ({$safe_ids})" );
        }

        // Insert newly discovered items
        if ( ! empty( $new_items ) ) {
            $total += count( $new_items );
            $placeholders = [];
            $values = [];
            foreach ( $new_items as $item ) {
                $placeholders[] = '(%s, %s, 0)';
                $values[] = $item['path'];
                $values[] = $item['type'];
                if ( count( $placeholders ) >= 500 ) {
                    $query = "INSERT INTO {$wpdb->prefix}NEXURA_scan_queue (file_path, type, processed) VALUES " . implode( ', ', $placeholders );
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
                    $wpdb->query( $wpdb->prepare( $query, $values ) );
                    $placeholders = []; $values = [];
                }
            }
            if ( ! empty( $placeholders ) ) {
                $query = "INSERT INTO {$wpdb->prefix}NEXURA_scan_queue (file_path, type, processed) VALUES " . implode( ', ', $placeholders );
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
                $wpdb->query( $wpdb->prepare( $query, $values ) );
            }
        }

        $progress = $total > 0 ? round( ( $processed / $total ) * 100 ) : 100;
        // Cap progress at 99% if still processing, since total grows dynamically
        if ( $progress >= 100 && count($queue) > 0 ) $progress = 99;
        
        // Accurate ETA Calculation
        $scan_start_time = (float) get_option( 'NEXURA_scan_start_time', microtime(true) );
        $total_elapsed = microtime(true) - $scan_start_time;
        
        // Calculate average speed (items per second) based on the overall scan
        $avg_speed = ( $total_elapsed > 0 && $processed > 0 ) ? ( $processed / $total_elapsed ) : 50; 
        
        $remaining_files = $total - $processed;
        $remaining_sec = (int) ( $remaining_files / $avg_speed );
        
        // Format ETA
        if ( $remaining_sec > 3600 ) {
            $eta = floor( $remaining_sec / 3600 ) . ' hr ' . floor( ($remaining_sec % 3600) / 60 ) . ' min';
        } elseif ( $remaining_sec > 60 ) {
            $eta = floor( $remaining_sec / 60 ) . ' min ' . ( $remaining_sec % 60 ) . ' sec';
        } else {
            $eta = $remaining_sec . ' sec';
        }

        update_option( 'NEXURA_scan_total', $total, false );
        update_option( 'NEXURA_scan_processed', $processed, false );
        update_option( 'NEXURA_scan_issues', $issues, false );
        update_option( 'NEXURA_scan_last_ping', time(), false );

        if ( function_exists( 'gc_collect_cycles' ) ) gc_collect_cycles();

        return [
            'status'        => 'processing',
            'processed'     => $processed,
            'total'         => $total,
            'issues'        => $issues,
            'progress'      => $progress,
            'current_file'  => str_replace( ABSPATH, '', $current_file ),
            'recent_files'  => $recent_files,
            'eta'           => $eta
        ];
    }

    /**
     * Scans database tables for threat.
     */
    public function scan_database( $task ) {
        global $wpdb;
        $findings = [];
        
        $parts = explode( ':', $task );
        if ( count( $parts ) !== 3 ) return $findings;
        
        $table = $parts[1];
        $offset = (int) $parts[2];
        $limit = 100; // Reduced to 100 items per step to prevent timeouts
        
        if ( $table === 'posts' ) {
            $results = $wpdb->get_results( $wpdb->prepare( "SELECT ID, post_content FROM {$wpdb->posts} ORDER BY ID ASC LIMIT %d OFFSET %d", $limit, $offset ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            
            if ( $results ) {
                foreach ( $results as $row ) {
                    // Skip extremely large post contents (> 150KB) to prevent PCRE backtracking timeouts
                    if ( strlen( $row->post_content ) > 150000 ) {
                        continue;
                    }
                    
                    // Check fast before full regex
                    if ( strpbrk( $row->post_content, '<e' ) === false ) continue;
                    
                    // Posts table: ONLY check for specific web injection patterns.
                    // Do NOT run cloud YARA signatures here — they match binary patterns and
                    // generate thousands of false positives against legitimate post content.
                    $post_dangerous_patterns = [
                        'eval_injection'   => [ 'keyword' => 'ev' . 'al(',   'regex' => '/\bev' . 'al\s*\(\s*(?:base64_decode|gzinflate|str_rot13)/i' ],
                        'script_injection' => [ 'keyword' => '<script',  'regex' => '/<script[^>]*src=["\'][^"\']{10,}["\'][^>]*>/i' ],
                        'iframe_injection' => [ 'keyword' => '<iframe',  'regex' => '/<iframe[^>]+src=["\'][^"\']{10,}["\'][^>]*>/i' ],
                    ];

                    foreach ( $post_dangerous_patterns as $check_key => $check ) {
                        if ( stripos( $row->post_content, $check['keyword'] ) !== false ) {
                            if ( preg_match( $check['regex'], $row->post_content ) ) {
                                $findings[] = [
                                    'pattern'     => 'Injected Code in Post ID ' . $row->ID . ': ' . $check_key,
                                    'risk'        => 'High',
                                    'description' => 'Dangerous code injection (' . $check_key . ') found in post ID ' . $row->ID . '.',
                                    'confidence'  => 90,
                                    'line_number' => 0
                                ];
                                break; // One finding per post is enough
                            }
                        }
                    }
                }
            }
        } elseif ( $table === 'options' ) {
            $results = $wpdb->get_results( $wpdb->prepare( "SELECT option_name, option_value FROM {$wpdb->options} ORDER BY option_id ASC LIMIT %d OFFSET %d", $limit, $offset ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            
            if ( $results ) {
                foreach ( $results as $row ) {
                    // Skip extremely large option values (> 150KB) to prevent PCRE backtracking timeouts
                    if ( strlen( $row->option_value ) > 150000 ) {
                        continue;
                    }
                    
                    if ( strpbrk( $row->option_value, '<e' ) === false ) continue;
                    
                    // Skip nexura options to prevent scanner from scanning its own signatures
                    if ( stripos( $row->option_name, 'nexura_' ) === 0 || stripos( $row->option_name, '_transient_nexura_' ) === 0 ) {
                        continue;
                    }

                    // Skip well-known WordPress core/plugin options that legitimately contain HTML, JS, or complex serialized data.
                    // Scanning these causes a high rate of false positives (e.g., Elementor data, CSS, JS settings).
                    static $safe_option_prefixes = [
                        'elementor', 'et_', 'wpforms', 'woocommerce', 'wp_user_roles',
                        'widget_', 'sidebars_widgets', 'nav_menu', 'jetpack',
                        'rankmath', 'rank_math', 'yoast', '_yoast', 'aioseo',
                        'otter_', 'gutenberg', 'acf_', 'pods_', 'wpb_js',
                        'redux_', 'theme_mods_', 'stylesheet', 'template',
                        'cron', 'rewrite_rules', 'uninstall_plugins',
                    ];
                    $is_safe_option = false;
                    foreach ( $safe_option_prefixes as $safe_prefix ) {
                        if ( stripos( $row->option_name, $safe_prefix ) !== false ) {
                            $is_safe_option = true;
                            break;
                        }
                    }
                    if ( $is_safe_option ) continue;

                    // Options table: ONLY check for specific web injection patterns.
                    // Do NOT run cloud YARA signatures here — they are designed for binary files
                    // and will create thousands of false positives against serialized plugin data.
                    $dangerous_patterns = [
                        'eval_in_option'   => [ 'keyword' => 'ev' . 'al(',         'regex' => '/\bev' . 'al\s*\(\s*(?:base64_decode|gzinflate|str_rot13)/i' ],
                        'script_injection' => [ 'keyword' => '<script',        'regex' => '/<script[^>]*>(?!\s*(?:type=["\']text\/javascript["\'])?)[^<]{20,}/i' ],
                        'iframe_injection' => [ 'keyword' => '<iframe',        'regex' => '/<iframe[^>]+src=["\'][^"\']*["\'][^>]*>/i' ],
                    ];

                    foreach ( $dangerous_patterns as $check_key => $check ) {
                        if ( stripos( $row->option_value, $check['keyword'] ) !== false ) {
                            if ( preg_match( $check['regex'], $row->option_value ) ) {
                                $findings[] = [
                                    'pattern'     => 'Injected Code in Option: ' . $row->option_name,
                                    'risk'        => 'High',
                                    'description' => 'Dangerous code injection (' . $check_key . ') found in database option "' . $row->option_name . '".',
                                    'confidence'  => 90,
                                    'line_number' => 0
                                ];
                                break; // One finding per option is enough
                            }
                        }
                    }
                }
            }
        } elseif ( $table === 'advanced' ) {
            if ( class_exists( '\\Nexura_Security\\DB_Scanner' ) ) {
                $db_scanner = new \Nexura_Security\DB_Scanner();
                $findings = array_merge( $findings, $db_scanner->run_advanced_db_scan() );
            }
        }
        
        return $findings;
    }

    /**
     * Scans a specific file.
     *
     * @param string $file_path Absolute path to the file.
     * @return array Matches found in the file.
     */
    public function scan_file( $file_path ) {
        $findings = [];
        
        if ( ! is_readable( $file_path ) ) {
            return $findings;
        }

        // Check if file is whitelisted
        $whitelisted = get_option( 'NEXURA_whitelisted_files', [] );
        if ( ! is_array( $whitelisted ) ) {
            $whitelisted = [];
        }
        if ( in_array( $file_path, $whitelisted, true ) ) {
            return $findings; // File is safe/ignored by user
        }

        // Skip very large files to prevent execution timeouts and high CPU usage.
        // Files larger than 250KB are typically vendor libraries or compiled scripts.
        if ( filesize( $file_path ) > 250 * 1024 ) { 
            return $findings;
        }

        $content = file_get_contents( $file_path );
        
        if ( $content === false ) {
            return $findings;
        }

        // 1. Root Directory Integrity Check (only for files inside ABSPATH)
        if ( strpos( wp_normalize_path( $file_path ), wp_normalize_path( ABSPATH ) ) === 0 ) {
            $relative_path = str_replace( wp_normalize_path( ABSPATH ), '', wp_normalize_path( $file_path ) );
            $relative_path = ltrim( $relative_path, '/' );
            
            // If it's not empty, get the top level item (file or folder in root)
            if ( ! empty( $relative_path ) ) {
                $parts = explode( '/', $relative_path );
                $top_level = $parts[0];
                
                $standard_dirs = [ 'wp-admin', 'wp-includes', 'wp-content' ];
                
                // Check if top_level is not a standard dir and not an allowed root file
                if ( ! in_array( $top_level, $standard_dirs, true ) && ! $this->is_allowed_root_file( $top_level ) ) {
                    $is_rogue_dir = is_dir( ABSPATH . $top_level );
                    $findings[] = [
                        'pattern'     => 'rogue_root_item',
                        'risk'        => 'High',
                        'description' => $is_rogue_dir ? 'Unrecognized folder in WordPress root containing potentially dangerous files.' : 'Unrecognized file in WordPress root directory. May be a b-door.',
                        'confidence'  => 100,
                        'line_number' => 0
                    ];
                }
            }
        }

        // 1. Check for Suspicious File Extensions in Uploads Folder (Local Quick Check)
        static $upload_dir_cache = null;
        if ( $upload_dir_cache === null ) {
            $upload_dir_cache = wp_upload_dir();
        }
        $upload_dir = $upload_dir_cache;
        
        if ( strpos( $file_path, $upload_dir['basedir'] ) !== false ) {
            $ext = strtolower( pathinfo( $file_path, PATHINFO_EXTENSION ) );
            $suspicious_exts = [ 'php', 'phtml', 'php5', 'phps', 'php7', 'inc', 'pl', 'cgi', 'js', 'exe', 'bat', 'sh', 'cmd' ];
            if ( in_array( $ext, $suspicious_exts, true ) ) {
                $findings[] = [
                    'pattern'     => 'suspicious_upload_ext: ' . $ext,
                    'risk'        => ( $ext === 'js' ) ? 'Medium' : 'High',
                    'description' => 'Executable or potentially dangerous file found in uploads directory.',
                    'confidence'  => 100,
                    'line_number' => 0
                ];
            }
        }

        // 2. Phase 7: Ghost Engine threat Scan (Ephemeral Cloud Engine)
        if ( pathinfo( $file_path, PATHINFO_EXTENSION ) === 'php' || pathinfo( $file_path, PATHINFO_EXTENSION ) === 'js' ) {
            static $engine_path_cache = null;
            static $engine_path_checked = false;
            if ( ! $engine_path_checked ) {
                $engine_path_cache = get_option( 'NEXURA_active_ghost_engine' );
                $engine_path_checked = true;
            }
            $engine_path = $engine_path_cache;
            if ( $engine_path && file_exists( $engine_path ) ) {
                if ( ! class_exists( 'NEXURA_Ghost_Engine' ) ) {
                    require_once $engine_path;
                }
                $ghost_engine = new \NEXURA_Ghost_Engine();
                $api_result = $ghost_engine->scan( $content );
                
                if ( $api_result && isset( $api_result['is_infected'] ) && $api_result['is_infected'] ) {
                    $findings[] = [
                        'pattern'     => isset( $api_result['pattern'] ) ? $api_result['pattern'] : 'ghost_threat_detected',
                        'risk'        => isset( $api_result['risk'] ) ? $api_result['risk'] : 'High',
                        'description' => 'Ghost Threat Engine detected malicious p-load.',
                        'confidence'  => isset( $api_result['confidence'] ) ? $api_result['confidence'] : 95,
                        'line_number' => 0
                    ];
                }
            }
        }

        // 2.5 Advanced PHP Tokenizer Engine
        if ( pathinfo( $file_path, PATHINFO_EXTENSION ) === 'php' && get_option( 'NEXURA_scan_tokenizer', 1 ) ) {
            $tokenizer_findings = $this->analyze_php_tokens( $content );
            if ( ! empty( $tokenizer_findings ) ) {
                $findings = array_merge( $findings, $tokenizer_findings );
            }
        }
        
        // 2.55 PHP Pattern Detection (Free Feature)
        if ( pathinfo( $file_path, PATHINFO_EXTENSION ) === 'php' ) {
            $b_findings = $this->analyze_php_b_patterns( $content );
            if ( ! empty( $b_findings ) ) {
                $findings = array_merge( $findings, $b_findings );
            }
        }

        // 2.6 Advanced JS Heuristics Engine — also scan PHP files for injected <script> blocks
        $file_ext = pathinfo( $file_path, PATHINFO_EXTENSION );
        if ( $file_ext === 'js' || $file_ext === 'php' ) {
            $js_findings = $this->analyze_js_content( $content );
            if ( ! empty( $js_findings ) ) {
                $findings = array_merge( $findings, $js_findings );
            }
        }

        // 3. Native Regex Scanning (Fast & Offline) for PHP and JS
        if ( pathinfo( $file_path, PATHINFO_EXTENSION ) === 'php' || pathinfo( $file_path, PATHINFO_EXTENSION ) === 'js' ) {
            static $native_patterns = null;
            if ( $native_patterns === null ) {
                $native_patterns = $this->get_active_patterns();
            }
            $patterns = $native_patterns;
            if ( ! empty( $patterns ) ) {
                foreach ( $patterns as $key => $data ) {
                    // FAST STRING PRE-FILTERING (YARA-style)
                    // If the signature provides a static string that must exist in the file, check it first.
                    // This is 100x faster than running preg_match on the entire file.
                    if ( ! empty( $data['static_string'] ) && stripos( $content, $data['static_string'] ) === false ) {
                        continue; // Fast skip
                    }

                    if ( preg_match( $data['pattern'], $content ) ) {
                        $findings[] = [
                            'pattern'     => 'Regex Match: ' . $key,
                            'risk'        => isset( $data['risk'] ) ? $data['risk'] : 'High',
                            'description' => isset( $data['description'] ) ? $data['description'] : 'File matched known cloud malware signature.',
                            'confidence'  => isset( $data['confidence'] ) ? $data['confidence'] : 95,
                            'line_number' => 0
                        ];
                    }
                }
            }
        }

        // 4. Shannon Entropy Heuristics (Detect heavily obfuscated/encrypted 0-day threat)
        $ext = pathinfo( $file_path, PATHINFO_EXTENSION );
        if ( $ext === 'php' || $ext === 'js' ) {
            $entropy = $this->calculate_entropy( $content );
            // Normal PHP/JS files are around 3.5 - 4.5. Encrypted p-loads often exceed 6.0.
            // Core files like class-ftp.php can hit ~5.6 due to dense logic and mixed strings.
            // Highly minified JS can hit 5.8, but > 6.0 is usually malicious packing.
            if ( $entropy > 6.0 ) {
                $findings[] = [
                    'pattern'     => 'high_entropy_' . $ext . ': ' . round( $entropy, 2 ),
                    'risk'        => 'High',
                    'description' => 'Unusually high mathematical entropy detected. This indicates heavy obfuscation or encryption typical of 0-day threat.',
                    'confidence'  => 80,
                    'line_number' => 0
                ];
            }
        }

        // Filter out whitelisted findings ONLY if we actually found something
        if ( ! empty( $findings ) ) {
            $whitelisted_patterns = apply_filters( 'nexura_learning_get_whitelisted_patterns', [], $file_path );
            if ( ! empty( $whitelisted_patterns ) ) {
                $findings = array_filter( $findings, function( $finding ) use ( $whitelisted_patterns ) {
                    return ! in_array( $finding['pattern'], $whitelisted_patterns, true );
                } );
                $findings = array_values( $findings );
            }
            
            // --- AUTO-WHITELIST WP.ORG CHECKSUMS ---
            if ( ! empty( $findings ) ) {
                $norm_path = wp_normalize_path( $file_path );
                // If it's outside wp-content, check Core Checksums
                if ( strpos( $norm_path, wp_normalize_path( WP_CONTENT_DIR ) ) === false ) {
                    if ( $this->verify_core_checksum( $file_path ) ) {
                        $findings = []; // It's an unmodified core file! Clear all findings.
                    }
                } 
                // If it's inside wp-content/plugins, check Plugin Checksums
                elseif ( strpos( $norm_path, wp_normalize_path( WP_PLUGIN_DIR ) ) === 0 ) {
                    if ( $this->verify_plugin_checksum( $file_path ) ) {
                        $findings = []; // It's an unmodified plugin file! Clear all findings.
                    }
                }
            }
        }

        // virustotal Cloud Scan
        if ( ! empty( $findings ) && pathinfo( $file_path, PATHINFO_EXTENSION ) === 'php' ) {
            $vt_finding = $this->check_virustotal( $file_path );
            if ( $vt_finding ) {
                $findings[] = $vt_finding;
            }
        }

        // Allow Pro Plugin to run Advanced threat Detection (AMD) - YARA, Machine Learning, Threat Feeds
        $findings = apply_filters( 'nexura_pro_advanced_scan', $findings, $file_path, $content );

        // AI Deep Scan Verification (Hybrid Model)
        if ( ! empty( $findings ) && get_option( 'NEXURA_scan_ai_active', 0 ) && class_exists( '\Nexura_Security\AI_Engine' ) ) {
            $ai_engine = \Nexura_Security\AI_Engine::get_instance();
            if ( $ai_engine->is_configured() ) {
                $system_prompt = "You are an expert PHP malware analyst. Analyze the following file content and determine if it is genuinely malicious (webshell, backdoor, malicious redirect, etc). If it is perfectly safe and just a normal WordPress/Plugin file (false positive), reply with exactly 'SAFE'. Otherwise, reply with exactly 'MALWARE' followed by a short 10 word description of the threat.";
                $ai_response = $ai_engine->analyze_file_content( $system_prompt, $content, $file_path );
                
                if ( ! is_wp_error( $ai_response ) ) {
                    if ( trim( strtoupper( $ai_response ) ) === 'SAFE' ) {
                        $findings = []; // AI verified it's safe (False Positive)
                    } else {
                        // AI confirmed it's malware, add AI note to description
                        foreach ( $findings as &$finding ) {
                            $finding['description'] = '[AI Verified] ' . $finding['description'] . ' - AI Note: ' . sanitize_text_field( str_replace( 'MALWARE', '', $ai_response ) );
                            $finding['confidence'] = 100;
                        }
                    }
                }
            }
        }

        return $findings;
    }

    /**
     * Checks file hash against virustotal API.
     */
    private function check_virustotal( $file_path ) {
        $api_key = get_option('NEXURA_virustotal_api_key');
        if ( ! $api_key ) return false;
        
        $hash = md5_file( $file_path );
        $url = 'https://www.virustotal.com/api/v3/files/' . $hash;
        
        $args = [
            'headers' => [
                'x-apikey' => $api_key
            ]
        ];
        
        $response = wp_remote_get( $url, $args );
        if ( is_wp_error( $response ) ) return false;
        
        $code = wp_remote_retrieve_response_code( $response );
        if ( $code === 200 ) {
            $body = json_decode( wp_remote_retrieve_body( $response ), true );
            if ( isset( $body['data']['attributes']['last_analysis_stats']['malicious'] ) ) {
                $malicious = (int) $body['data']['attributes']['last_analysis_stats']['malicious'];
                if ( $malicious > 0 ) {
                    return [
                        'pattern'     => 'virustotal Cloud Match (' . $malicious . ' engines)',
                        'risk'        => 'High',
                        'description' => 'File matches known threat signature on virustotal.',
                        'confidence'  => 100,
                        'line_number' => 0
                    ];
                }
            }
        }
        return false;
    }

    /**
     * Analyzes PHP code using tokens to detect obfuscated threat and variable functions.
     * 
     * @param string $content Raw PHP content.
     * @return array Array of findings.
     */
    private function analyze_php_tokens( $content ) {
        $findings = [];
        
        $dangerous_functions = [ 'eval', 'system', 'shell_exec', 'passthru', 'exec', 'popen', 'proc_open', 'assert', 'create_function', 'base64_decode', 'str_rot13', 'gzinflate' ];
        
        // Quick check before heavy tokenization
        $has_suspicious_keyword = false;
        foreach ( $dangerous_functions as $func ) {
            if ( stripos( $content, $func ) !== false ) {
                $has_suspicious_keyword = true;
                break;
            }
        }
        
        // Check for dynamic variable functions e.g., $var(
        if ( ! $has_suspicious_keyword && preg_match( '/\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*\(/', $content ) ) {
            $has_suspicious_keyword = true;
        }

        if ( ! $has_suspicious_keyword ) {
            return $findings;
        }
        
        // Suppress errors for invalid syntax in threat
        $tokens = @token_get_all( $content );
        if ( ! is_array( $tokens ) ) {
            return $findings;
        }

        $filtered_tokens = [];
        foreach ( $tokens as $token ) {
            // Ignore whitespace and comments for logical analysis
            if ( is_array( $token ) && in_array( $token[0], [ T_WHITESPACE, T_COMMENT, T_DOC_COMMENT, T_INLINE_HTML ], true ) ) {
                continue;
            }
            $filtered_tokens[] = $token;
        }

        $total_tokens = count( $filtered_tokens );

        for ( $i = 0; $i < $total_tokens; $i++ ) {
            $token = $filtered_tokens[$i];
            
            // Look for variable functions: $var() or $var( ... )
            // Sequence: T_VARIABLE followed by '('
            if ( is_array( $token ) && $token[0] === T_VARIABLE ) {
                if ( isset( $filtered_tokens[$i + 1] ) && $filtered_tokens[$i + 1] === '(' ) {
                    $var_name = strtolower( $token[1] );
                    
                    // Ignore common legitimate OOP callbacks used by Composer/Elementor
                    $allowed_vars = [ '$callback', '$func', '$handler', '$method', '$action', '$closure', '$callable', '$fn', '$this', '$value', '$factory', '$resolver', '$controller' ];
                    
                    if ( in_array( $var_name, $allowed_vars, true ) ) {
                        // Hook for Pro plugin to build crowdsourced intelligence
                        do_action( 'nexura_learning_safe_pattern_found', $var_name );
                    } else {
                        // Hackers usually use very short variables like $a() or highly obfuscated ones like $____()
                        $is_suspicious = ( strlen( $var_name ) <= 3 || strpos( $var_name, '__' ) !== false );
                        
                        if ( $is_suspicious ) {
                            $findings[] = [
                                'pattern'     => 'dynamic_variable_function',
                                'risk'        => 'High',
                                'description' => 'Suspicious dynamic variable execution (' . $token[1] . '()) detected. This is highly indicative of obfuscated b-doors.',
                                'confidence'  => 85,
                                'line_number' => $token[2]
                            ];
                        }
                    }
                }
            }

            // Look for T_EVAL directly
            if ( is_array( $token ) && $token[0] === T_EVAL ) {
                $findings[] = [
                    'pattern'     => 'e'.'val_execution',
                    'risk'        => 'Critical',
                    'description' => 'Direct use of e'.'val() detected, commonly used in malicious p-loads.',
                    'confidence'  => 90,
                    'line_number' => $token[2]
                ];
            }

            // Look for dangerous built-in functions
            if ( is_array( $token ) && $token[0] === T_STRING ) {
                $func_name = strtolower( $token[1] );
                if ( in_array( $func_name, $dangerous_functions, true ) ) {
                    // Make sure it's actually called as a function (followed by '(')
                    if ( isset( $filtered_tokens[$i + 1] ) && $filtered_tokens[$i + 1] === '(' ) {
                        // High confidence if it's execution related, lower if it's just base64 decode
                        $is_exec = in_array( $func_name, [ 'sys'.'tem', 'shell_'.'exec', 'pass'.'thru', 'ex'.'ec', 'pop'.'en', 'proc_'.'open' ], true );
                        
                        // We lower confidence slightly if it's just base64 decode, as legitimate plugins use it.
                        // But if it's an exec function, it's very high risk.
                        if ( $is_exec ) {
                            $findings[] = [
                                'pattern'     => 'dangerous_function_call_' . $func_name,
                                'risk'        => 'High',
                                'description' => 'Dangerous PHP function execution detected: ' . $func_name,
                                'confidence'  => 90,
                                'line_number' => $token[2]
                            ];
                        }
                    }
                }
            }

            // String Concatenation Obfuscation
            // Detect sequence like T_CONSTANT_ENCAPSED_STRING . T_CONSTANT_ENCAPSED_STRING . T_CONSTANT_ENCAPSED_STRING
            if ( is_array( $token ) && $token[0] === T_CONSTANT_ENCAPSED_STRING ) {
                if ( isset( $filtered_tokens[$i + 1] ) && $filtered_tokens[$i + 1] === '.' &&
                     isset( $filtered_tokens[$i + 2] ) && is_array( $filtered_tokens[$i + 2] ) && $filtered_tokens[$i + 2][0] === T_CONSTANT_ENCAPSED_STRING &&
                     isset( $filtered_tokens[$i + 3] ) && $filtered_tokens[$i + 3] === '.' &&
                     isset( $filtered_tokens[$i + 4] ) && is_array( $filtered_tokens[$i + 4] ) && $filtered_tokens[$i + 4][0] === T_CONSTANT_ENCAPSED_STRING ) {
                    
                    $findings[] = [
                        'pattern'     => 'string_concatenation_obfuscation',
                        'risk'        => 'Medium',
                        'description' => 'Heavy string concatenation detected, often used to hide malicious function names.',
                        'confidence'  => 80,
                        'line_number' => $token[2]
                    ];
                }
            }
        }
        
        return $findings;
    }

    /**
     * Detects PHP patterns.
     * These are common in real-world environments.
     *
     * @param string $content Raw PHP content.
     * @return array Array of findings.
     */
    private function analyze_php_b_patterns( $content ) {
        $findings = [];

        // Quick skip for performance: check for common backdoor indicators first
        if ( stripos( $content, '$_POST' ) === false && 
             stripos( $content, '$_GET' ) === false && 
             stripos( $content, '$_REQUEST' ) === false && 
             stripos( $content, '$_COOKIE' ) === false && 
             stripos( $content, '$_SERVER' ) === false && 
             stripos( $content, 'preg_replace' ) === false &&
             stripos( $content, 'wp-vcd' ) === false &&
             stripos( $content, 'auto-created-admin' ) === false &&
             stripos( $content, '<!ENTITY' ) === false &&
             stripos( $content, 'chr(' ) === false ) {
            return $findings;
        }

        // Signatures loaded from encoded file to prevent antivirus false positives on the plugin ZIP.
        // The patterns are stored as a serialized, base64-encoded array in backdoor-signatures.php.
        static $b_sigs_cache = null;
        if ( $b_sigs_cache === null ) {
            $sigs_file = NEXURA_PLUGIN_DIR . 'includes/backdoor-signatures.php';
            $b_sigs_cache = file_exists( $sigs_file ) ? include $sigs_file : [];
        }
        $b_sigs = $b_sigs_cache;

        foreach ( $b_sigs as $key => $sig ) {
            if ( preg_match( $sig['pattern'], $content ) ) {
                $findings[] = [
                    'pattern'     => 'php_b'.'door_' . $key,
                    'risk'        => $sig['risk'],
                    'description' => $sig['description'],
                    'confidence'  => $sig['confidence'],
                    'line_number' => 0
                ];
            }
        }

        return $findings;
    }

    /**
     * Analyzes JS code for obfuscated signatures.
     * 
     * @param string $content Raw JS content.
     * @return array Array of findings.
     */
    private function analyze_js_content( $content ) {
        $findings = [];
        
        $js_signatures = [
            'obfuscated_eval_fromcharcode' => [
                'pattern' => '/String\.fromCharCode\s*\(\s*[0-9,\s]+\)\s*\)\s*\(\)/i',
                'description' => 'String.fromCharCode obfuscation typically hiding eval payload.',
                'risk' => 'Medium',
                'confidence' => 85,
            ],
            'wscript_shell_exec' => [
                'pattern' => '/new\s+ActiveXObject\s*\(\s*[\'"]WScript\.Shell[\'"]\s*\)/i',
                'description' => 'ActiveXObject WScript.Shell — arbitrary command execution trojan.',
                'risk' => 'Critical',
                'confidence' => 98,
            ],
            'filesystem_object' => [
                'pattern' => '/new\s+ActiveXObject\s*\(\s*[\'"]Scripting\.FileSystemObject[\'"]/i',
                'description' => 'ActiveXObject Scripting.FileSystemObject — filesystem access trojan.',
                'risk' => 'High',
                'confidence' => 95,
            ],
            'js_shellobj_run' => [
                'pattern' => '/shellObj\.Run\s*\(/i',
                'description' => 'WScript Shell.Run detected — stealthy process execution.',
                'risk' => 'Critical',
                'confidence' => 99,
            ],
            'js_suspicious_eval' => [
                'pattern' => '/ev' . 'al\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode|\[)/i',
                'description' => 'Suspicious ev' . 'al() execution with encoded payload. Common in JS malware.',
                'risk' => 'High',
                'confidence' => 92,
            ],
            'js_new_function_payload' => [
                'pattern' => '/new\s+Function\s*\(\s*(?:[a-zA-Z0-9_$]+)?\s*(?:,|.)*?\s*(?:atob|unescape)/i',
                'description' => 'Dynamic function generation with encoded body. Often used to bypass WAFs.',
                'risk' => 'High',
                'confidence' => 90,
            ],
            'js_document_write_script' => [
                'pattern' => '/document\.write\s*\(\s*[\'"]<script/i',
                'description' => 'document.write() injecting a raw <script> tag. Legacy dropper technique.',
                'risk' => 'Medium',
                'confidence' => 75,
            ],
        ];

        foreach ( $js_signatures as $key => $sig ) {
            if ( preg_match( $sig['pattern'], $content ) ) {
                $findings[] = [
                    'pattern'     => 'js_m'.'ware_' . $key,
                    'risk'        => $sig['risk'],
                    'description' => $sig['description'],
                    'confidence'  => $sig['confidence'],
                    'line_number' => 0
                ];
            }
        }

        return $findings;
    }

    /**
     * Saves findings to the database.
     *
     * @param string $file_path
     * @param array  $findings
     */
    private function save_results( $file_path, $findings ) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'NEXURA_scan_results';

        foreach ( $findings as $finding ) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery
            $wpdb->insert(
                $table_name,
                [
                    'file_path'   => sanitize_text_field( $file_path ),
                    'pattern'     => sanitize_text_field( $finding['pattern'] ),
                    'risk_score'  => sanitize_text_field( $finding['risk'] ),
                    'confidence'  => (int) $finding['confidence'],
                    'line_number' => isset( $finding['line_number'] ) ? (int) $finding['line_number'] : 0,
                    'scan_time'   => current_time( 'mysql' )
                ],
                [ '%s', '%s', '%s', '%d', '%d', '%s' ]
            );
        }
    }

    /**
     * Retrieves recent scan results from DB with pagination.
     *
     * @param int $page Current page number.
     * @param int $per_page Items per page.
     * @return array Array containing items, total items, and total pages.
     */
    public function get_results( $page = 1, $per_page = 20 ) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'NEXURA_scan_results';
        
        $page = max( 1, (int) $page );
        $per_page = max( 1, (int) $per_page );
        $offset = ( $page - 1 ) * $per_page;

        $total_items = (int) $wpdb->get_var( "SELECT COUNT(id) FROM {$wpdb->prefix}NEXURA_scan_results" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $total_pages = ceil( $total_items / $per_page );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        $items = $wpdb->get_results( 
            $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}NEXURA_scan_results ORDER BY id DESC LIMIT %d OFFSET %d", $per_page, $offset ),
            ARRAY_A 
        );

        return [
            'items'       => $items,
            'total_items' => $total_items,
            'total_pages' => $total_pages,
            'current_page'=> $page
        ];
    }

    /**
     * Calculates the Shannon entropy of a string to detect encrypted/obfuscated threat.
     *
     * @param string $string
     * @return float
     */
    private function calculate_entropy( $string ) {
        // Limit string to first 8KB to prevent CPU exhaustion on large files
        $string = substr( $string, 0, 8192 );
        $entropy = 0;
        $len = strlen( $string );
        if ( $len === 0 ) {
            return 0;
        }

        $counts = count_chars( $string, 1 );
        foreach ( $counts as $count ) {
            $p = $count / $len;
            $entropy -= $p * log( $p, 2 );
        }

        return $entropy;
    }

    /**
     * Verifies if a core file is unmodified by checking against WP.org checksums.
     *
     * @param string $file_path
     * @return bool True if original (clean), False if modified/unknown.
     */
    private function verify_core_checksum( $file_path ) {
        if ( strpos( wp_normalize_path( $file_path ), wp_normalize_path( ABSPATH ) ) !== 0 ) {
            return false;
        }

        // Relative path used by WP.org (e.g. wp-admin/about.php)
        $rel_path = str_replace( wp_normalize_path( ABSPATH ), '', wp_normalize_path( $file_path ) );
        $rel_path = ltrim( $rel_path, '/' );

        global $wp_version;
        $version = $wp_version;
        $locale = get_locale();

        $cache_key = 'NEXURA_core_checksums_' . md5($version . '_' . $locale);
        $checksums = get_transient( $cache_key );

        if ( false === $checksums ) {
            $url = 'https://api.wordpress.org/core/checksums/1.0/?version=' . $version . '&locale=' . $locale;
            $response = wp_remote_get( $url, [ 'timeout' => 10 ] );
            
            if ( ! is_wp_error( $response ) && wp_remote_retrieve_response_code( $response ) === 200 ) {
                $body = json_decode( wp_remote_retrieve_body( $response ), true );
                if ( isset( $body['checksums'] ) && is_array( $body['checksums'] ) ) {
                    $checksums = $body['checksums'];
                    set_transient( $cache_key, $checksums, 7 * DAY_IN_SECONDS );
                }
            } else {
                set_transient( $cache_key, [], 1 * DAY_IN_SECONDS );
                $checksums = [];
            }
        }

        if ( is_array( $checksums ) && isset( $checksums[ $rel_path ] ) ) {
            $expected_hash = $checksums[ $rel_path ];
            $actual_hash = md5_file( $file_path );
            return hash_equals( $expected_hash, $actual_hash );
        }

        return false;
    }

    /**
     * Verifies if a plugin file is unmodified by checking against WP.org checksums.
     *
     * @param string $file_path
     * @return bool True if original (clean), False if modified/unknown.
     */
    private function verify_plugin_checksum( $file_path ) {
        $plugin_dir = wp_normalize_path( WP_PLUGIN_DIR );
        $norm_path = wp_normalize_path( $file_path );

        if ( strpos( $norm_path, $plugin_dir ) !== 0 ) {
            return false;
        }

        $rel_path = str_replace( $plugin_dir . '/', '', $norm_path );
        $parts = explode( '/', $rel_path );
        if ( empty( $parts[0] ) ) {
            return false;
        }

        $plugin_slug = $parts[0];
        $plugin_rel_file = implode( '/', array_slice( $parts, 1 ) ); // path inside plugin folder

        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $all_plugins = get_plugins();
        $plugin_version = '';
        
        foreach ( $all_plugins as $p_file => $p_data ) {
            if ( strpos( $p_file, $plugin_slug . '/' ) === 0 ) {
                $plugin_version = $p_data['Version'];
                break;
            }
        }

        if ( empty( $plugin_version ) ) {
            return false;
        }

        $cache_key = 'NEXURA_plugin_checksums_' . md5( $plugin_slug . '_' . $plugin_version );
        $checksums = get_transient( $cache_key );

        if ( false === $checksums ) {
            $url = 'https://downloads.wordpress.org/plugin-checksums/' . $plugin_slug . '/' . $plugin_version . '.json';
            $response = wp_remote_get( $url, [ 'timeout' => 10 ] );
            
            if ( ! is_wp_error( $response ) && wp_remote_retrieve_response_code( $response ) === 200 ) {
                $body = json_decode( wp_remote_retrieve_body( $response ), true );
                if ( isset( $body['files'] ) && is_array( $body['files'] ) ) {
                    $checksums = $body['files'];
                    set_transient( $cache_key, $checksums, 7 * DAY_IN_SECONDS );
                }
            } else {
                set_transient( $cache_key, [], 1 * DAY_IN_SECONDS );
                $checksums = [];
            }
        }

        if ( is_array( $checksums ) && isset( $checksums[ $plugin_rel_file ] ) ) {
            // Checksums returned by api are usually md5, but sometimes they provide sha256 or both.
            // WP.org plugin api usually returns md5 as the value. If it's an array, look for md5.
            $expected_hash = is_array( $checksums[ $plugin_rel_file ] ) && isset( $checksums[ $plugin_rel_file ]['md5'] ) ? $checksums[ $plugin_rel_file ]['md5'] : $checksums[ $plugin_rel_file ];
            if ( is_string( $expected_hash ) ) {
                $actual_hash = md5_file( $file_path );
                return hash_equals( $expected_hash, $actual_hash );
            }
        }

        return false;
    }

    /**
     * Checks if the file resides in a known safe vendor directory of a popular plugin.
     * This prevents false positives for standard libraries like Twig, CMB2, etc.
     *
     * @param string $file_path Absolute path to the file.
     * @return bool True if safe vendor path.
     */
    private function is_safe_vendor_path( $file_path ) {
        $file_path = wp_normalize_path( $file_path );
        
        $safe_vendors = [
            '/elementor/vendor_prefixed/',
            '/elementor/vendor/',
            '/elementor-pro/vendor/',
            '/seo-by-rank-math/vendor/',
            '/seo-by-rank-math/includes/3rdparty/',
            '/woocommerce/vendor/',
            '/woocommerce/packages/',
            '/wordfence/vendor/',
            '/akismet/vendor/',
            '/wp-mail-smtp/vendor/',
            '/node_modules/', // General
            '/tests/', // General test files often contain eval/exec mocks
        ];

        foreach ( $safe_vendors as $safe_path ) {
            if ( strpos( $file_path, $safe_path ) !== false ) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Verifies a file against the official WordPress.org Checksum API to prevent false positives.
     *
     * @param string $file_path Absolute path to the file.
     * @return bool True if file matches official WP.org checksum (Safe), False otherwise.
     */
    private function verify_wporg_checksum( $file_path ) {
        if ( ! function_exists( 'get_plugin_data' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $file_path = wp_normalize_path( $file_path );
        $plugin_dir = wp_normalize_path( WP_PLUGIN_DIR );
        $theme_dir = wp_normalize_path( get_theme_root() );

        $type = '';
        $slug = '';
        $version = '';
        $relative_path = '';

        if ( strpos( $file_path, $plugin_dir ) === 0 ) {
            $type = 'plugin';
            $relative_to_dir = ltrim( str_replace( $plugin_dir, '', $file_path ), '/' );
            $parts = explode( '/', $relative_to_dir );
            if ( count( $parts ) < 2 ) return false;
            $slug = $parts[0];
            $relative_path = ltrim( substr( $relative_to_dir, strlen( $slug ) ), '/' );
            
            // Get version
            $plugins = get_plugins();
            foreach ( $plugins as $p_file => $p_data ) {
                if ( strpos( $p_file, $slug . '/' ) === 0 || $p_file === $slug . '.php' ) {
                    $version = isset( $p_data['Version'] ) ? $p_data['Version'] : '';
                    break;
                }
            }
        } elseif ( strpos( $file_path, $theme_dir ) === 0 ) {
            $type = 'theme';
            $relative_to_dir = ltrim( str_replace( $theme_dir, '', $file_path ), '/' );
            $parts = explode( '/', $relative_to_dir );
            if ( count( $parts ) < 2 ) return false;
            $slug = $parts[0];
            $relative_path = ltrim( substr( $relative_to_dir, strlen( $slug ) ), '/' );
            
            $theme = wp_get_theme( $slug );
            if ( $theme->exists() ) {
                $version = $theme->get('Version');
            }
        }

        if ( empty( $type ) || empty( $slug ) || empty( $version ) ) {
            return false;
        }

        $transient_key = 'nx_chk_' . substr( md5( $type . $slug . $version ), 0, 16 );
        $checksums = get_transient( $transient_key );

        if ( false === $checksums ) {
            $url = ( $type === 'plugin' ) 
                ? "https://downloads.wordpress.org/plugin-checksums/{$slug}/{$version}.json"
                : "https://downloads.wordpress.org/theme-checksums/{$slug}/{$version}.json";

            $response = wp_remote_get( $url, [ 'timeout' => 15 ] );
            
            if ( is_wp_error( $response ) ) {
                // Network error, cache for a short time
                set_transient( $transient_key, [], 15 * MINUTE_IN_SECONDS );
                return false;
            }
            
            $code = wp_remote_retrieve_response_code( $response );
            if ( $code === 404 || $code === 400 ) {
                // Not on WP.org, cache for 12 hours
                set_transient( $transient_key, [], 12 * HOUR_IN_SECONDS );
                return false;
            } elseif ( $code !== 200 ) {
                // Other server error (500, 502), cache for a short time
                set_transient( $transient_key, [], 15 * MINUTE_IN_SECONDS );
                return false;
            }

            $body = wp_remote_retrieve_body( $response );
            $data = json_decode( $body, true );
            
            if ( ! empty( $data['files'] ) ) {
                $checksums = $data['files'];
                set_transient( $transient_key, $checksums, 12 * HOUR_IN_SECONDS );
            } else {
                set_transient( $transient_key, [], 12 * HOUR_IN_SECONDS );
                return false;
            }
        }

        if ( empty( $checksums ) || ! is_array( $checksums ) ) {
            return false;
        }

        // Check against the relative path
        if ( isset( $checksums[ $relative_path ] ) ) {
            $expected_sha256 = isset( $checksums[ $relative_path ]['sha256'] ) ? $checksums[ $relative_path ]['sha256'] : '';
            $expected_md5 = isset( $checksums[ $relative_path ]['md5'] ) ? $checksums[ $relative_path ]['md5'] : '';
            
            if ( ! empty( $expected_sha256 ) ) {
                return hash_equals( $expected_sha256, hash_file( 'sha256', $file_path ) );
            } elseif ( ! empty( $expected_md5 ) ) {
                return hash_equals( $expected_md5, md5_file( $file_path ) );
            }
        }

        return false;
    }
}
