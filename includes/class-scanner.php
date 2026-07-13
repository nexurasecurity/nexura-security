<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Scanner
 * 
 * Core malware scanning engine.
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
            $content = @file_get_contents( $file_path );
            if ( $content ) {
                $this->active_patterns = json_decode( $content, true );
                return $this->active_patterns;
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
        if ( $wpdb->get_var( "SHOW TABLES LIKE '{$table_name}'" ) !== $table_name ) {
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
        $wpdb->query("TRUNCATE TABLE {$wpdb->prefix}NEXURA_scan_results"); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

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
        // intentionally below to build the list of directories to scan for malware.
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

        // Add Database Scan Batches
        $post_count = (int) $wpdb->get_var( "SELECT COUNT(ID) FROM {$wpdb->posts}" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        for ( $i = 0; $i < $post_count; $i += 500 ) {
            $items_queue[] = [ 'path' => "db_scan:posts:{$i}", 'type' => 'db' ];
        }
        
        $options_count = (int) $wpdb->get_var( "SELECT COUNT(option_id) FROM {$wpdb->options}" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        for ( $i = 0; $i < $options_count; $i += 500 ) {
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
    private function build_file_queue( $dir, &$files_queue ) {
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
                        '/wp-includes/Text/Diff/Engine/shell.php', // WP Core false positive
                        '/wp-includes/ID3/getid3.php',             // WP Core false positive
                        '/wp-includes/ID3/getid3.lib.php',         // WP Core false positive
                        '/wp-includes/kses.php',                   // WP Core false positive
                        '/shopbuilder_uploads/cache/',             // Cache JS/CSS
                        '/elementor/css/',                         // Cache JS/CSS
                        '/elementor/assets/js/',                   // Elementor JS false positives
                        '/wp-rocket/',                             // Cache files
                        '/vendor/squizlabs/php_codesniffer/'       // PHP CodeSniffer false positive
                    ];
                    
                    // Allow external whitelisting via hook
                    $whitelist = apply_filters( 'nexura_security_scanner_whitelist', $whitelist );
                    
                    $is_whitelisted = false;
                    foreach ( $whitelist as $w_path ) {
                        if ( strpos( $pathname, $w_path ) !== false ) {
                            $is_whitelisted = true;
                            break;
                        }
                    }
                    
                    if ( strpos( $file->getFilename(), '.NEXURA_ghost_' ) === 0 ) {
                        $is_whitelisted = true;
                    }

                    if ( $is_whitelisted ) {
                        continue;
                    }

                    $ext = strtolower( $file->getExtension() );
                    $skip_exts = [ 'css', 'scss', 'less', 'jpg', 'jpeg', 'png', 'gif', 'svg', 'webp', 'mp3', 'mp4', 'woff', 'woff2', 'ttf', 'eot', 'pdf', 'zip', 'tar', 'gz' ];
                    if ( ! in_array( $ext, $skip_exts, true ) ) {
                        $files_queue[] = $file->getPathname();
                    }
                }
            }
        } catch ( \Exception $e ) {
            // Log directory access errors
        }
    }

    /**
     * Recursively scans ABSPATH up to a specific depth to catch root-level malware,
     * ignoring standard WP directories which are scanned separately.
     */
    private function build_root_file_queue( $dir, &$files_queue, $depth ) {
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
                    $this->build_root_file_queue( $pathname, $files_queue, $depth + 1 );
                } elseif ( $file->isFile() ) {
                    $ext = strtolower( $file->getExtension() );
                    $filename = strtolower( $file->getFilename() );
                    
                    // We target high-risk root files: .php, .js, .htaccess, extensionless files, and common hacker drop files like .txt and .html
                    if ( in_array( $ext, [ 'php', 'js', 'inc', 'phtml', 'txt', 'html' ], true ) || $filename === '.htaccess' || empty( $ext ) ) {
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

            // Send Security Alert Email if issues found (Max 1 per 24 hours)
            if ( $issues > 0 ) {
                $last_email_time = (int) get_option( 'NEXURA_last_virus_alert_email', 0 );
                if ( time() - $last_email_time > 24 * 3600 ) {
                    $admin_email = get_option( 'admin_email' );
                    $site_url    = site_url();
                    $logo_url    = NEXURA_PLUGIN_URL . 'admin/img/Nexura-Security_log.jpg';
                    
                    $subject = sprintf( '[%s] Security Alert: %d Malware Threats Detected', get_bloginfo( 'name' ), $issues );
                    
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
        $max_execution_time = 4.0; // 4 seconds for safety
        $current_file = '';
        $recent_files = [];
        $processed_ids = [];
        $new_items = [];
        
        // Zero-Load Cloud Scanner: only enabled when ALL of these are true:
        //   1. The administrator has enabled Global Threat Intelligence (opt-in)
        //   2. The Pro cloud_scanner option is explicitly enabled
        //   3. A valid Pro license is active
        // This ensures workers.dev is NEVER called without explicit user consent.
        $use_cloud = false;
        if (
            get_option( 'NEXURA_enable_global_threat_intel', '0' ) === '1' &&
            get_option( 'nexura_pro_cloud_scanner', 0 ) &&
            function_exists( 'nexura_is_pro' ) && nexura_is_pro()
        ) {
            $use_cloud = true;
        }

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
                            $whitelist = [ '/nexura-security/', '/nexura-security-pro/', '/nexura-quarantine/', '/nexura-logs/', '/nexura-backups/', '/wp-rocket/', '/cache/' ];
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
                    // Queue for Cloud Hash check instead of scanning locally
                    $hash = md5_file( $file_path );
                    $cloud_batch_hashes[] = $hash;
                    $cloud_batch_files[$hash] = $file_path;
                } else {
                    $findings = $this->scan_file( $file_path );
                    if ( ! empty( $findings ) ) {
                        $this->save_results( $file_path, $findings );
                        $issues += count( $findings );
                    }
                }
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
            $cloud_response = wp_remote_post( 'https://sgs-db-worker.sentinel-guard-security.workers.dev/v1/scan/hash', [
                'body' => json_encode( [ 'hashes' => $cloud_batch_hashes ] ),
                'headers' => [ 'Content-Type' => 'application/json' ],
                'timeout' => 5
            ]);
            
            if ( ! is_wp_error( $cloud_response ) && wp_remote_retrieve_response_code( $cloud_response ) === 200 ) {
                $cloud_data = json_decode( wp_remote_retrieve_body( $cloud_response ), true );
                if ( isset( $cloud_data['unknown_hashes'] ) && is_array( $cloud_data['unknown_hashes'] ) ) {
                    // Deep scan required for unknown hashes
                    foreach ( $cloud_data['unknown_hashes'] as $uhash ) {
                        if ( isset( $cloud_batch_files[$uhash] ) ) {
                            $file_to_deep_scan = $cloud_batch_files[$uhash];
                            // Send file content to cloud for deep scan
                            $file_content = @file_get_contents( $file_to_deep_scan );
                            if ( $file_content ) {
                                $deep_res = wp_remote_post( 'https://sgs-db-worker.sentinel-guard-security.workers.dev/v1/scan/file', [
                                    'body' => [ 'file_content' => base64_encode( $file_content ), 'path' => $file_to_deep_scan ],
                                    'timeout' => 8
                                ]);
                                if ( ! is_wp_error( $deep_res ) ) {
                                    $deep_data = json_decode( wp_remote_retrieve_body( $deep_res ), true );
                                    if ( ! empty( $deep_data['threats'] ) ) {
                                        $this->save_results( $file_to_deep_scan, $deep_data['threats'] );
                                        $issues += count( $deep_data['threats'] );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Mark processed
        if ( ! empty( $processed_ids ) ) {
            // We physically delete processed items to keep table tiny and fast
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared
            $wpdb->query( "DELETE FROM {$wpdb->prefix}NEXURA_scan_queue WHERE id IN (" . implode( ',', $processed_ids ) . ")" );
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
        
        $batch_elapsed = microtime(true) - $start_time;
        $batch_processed = count( $processed_ids );
        $speed = ( $batch_elapsed > 0 && $batch_processed > 0 ) ? ( $batch_processed / $batch_elapsed ) : 50; 
        
        $remaining_files = $total - $processed;
        $remaining_sec = (int) ( $remaining_files / $speed );
        
        $eta = ( $remaining_sec > 60 ) ? floor( $remaining_sec / 60 ) . ' min ' . ( $remaining_sec % 60 ) . ' sec' : $remaining_sec . ' sec';

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
     * Scans database tables for malware.
     */
    public function scan_database( $task ) {
        global $wpdb;
        $findings = [];
        
        $parts = explode( ':', $task );
        if ( count( $parts ) !== 3 ) return $findings;
        
        $table = $parts[1];
        $offset = (int) $parts[2];
        $limit = 500;
        
        if ( $table === 'posts' ) {
            $results = $wpdb->get_results( $wpdb->prepare( "SELECT ID, post_content FROM {$wpdb->posts} ORDER BY ID ASC LIMIT %d OFFSET %d", $limit, $offset ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            
            if ( $results ) {
                foreach ( $results as $row ) {
                    // Check fast before full regex
                    if ( strpbrk( $row->post_content, '<e' ) === false ) continue;
                    
                    $patterns = $this->get_active_patterns();
                    if ( ! empty( $patterns ) ) {
                        foreach ( $patterns as $key => $data ) {
                            if ( isset( $data['pattern'] ) && preg_match( $data['pattern'], $row->post_content ) ) {
                                $findings[] = [
                                    'pattern'     => 'DB Post ID ' . $row->ID . ': ' . $key,
                                    'risk'        => $data['risk'],
                                    'description' => 'Malicious payload found in database post content.',
                                    'confidence'  => 100,
                                    'line_number' => 0
                                ];
                            }
                        }
                    }
                }
            }
        } elseif ( $table === 'options' ) {
            $results = $wpdb->get_results( $wpdb->prepare( "SELECT option_name, option_value FROM {$wpdb->options} ORDER BY option_id ASC LIMIT %d OFFSET %d", $limit, $offset ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            
            if ( $results ) {
                foreach ( $results as $row ) {
                    if ( strpbrk( $row->option_value, '<e' ) === false ) continue;
                    
                    // Skip nexura options to prevent scanner from scanning its own signatures
                    if ( stripos( $row->option_name, 'nexura_' ) === 0 || stripos( $row->option_name, '_transient_nexura_' ) === 0 ) {
                        continue;
                    }

                    static $active_patterns = null;
                    if ( $active_patterns === null ) {
                        $active_patterns = $this->get_active_patterns();
                    }
                    $patterns = $active_patterns;
                    if ( ! empty( $patterns ) ) {
                        foreach ( $patterns as $key => $data ) {
                            if ( isset( $data['pattern'] ) && preg_match( $data['pattern'], $row->option_value ) ) {
                                $findings[] = [
                                    'pattern'     => 'DB Option "' . $row->option_name . '": ' . $key,
                                    'risk'        => $data['risk'],
                                    'description' => 'Malicious payload found in database options.',
                                    'confidence'  => 100,
                                    'line_number' => 0
                                ];
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

        // Optional: Skip very large files to prevent memory exhaustion
        if ( filesize( $file_path ) > 5 * 1024 * 1024 ) { // 5MB limit
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
                        'description' => $is_rogue_dir ? 'Unrecognized folder in WordPress root containing potentially dangerous files.' : 'Unrecognized file in WordPress root directory. May be a backdoor.',
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

        // 2. Phase 7: Ghost Engine Malware Scan (Ephemeral Cloud Engine)
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
                        'pattern'     => isset( $api_result['pattern'] ) ? $api_result['pattern'] : 'ghost_malware_detected',
                        'risk'        => isset( $api_result['risk'] ) ? $api_result['risk'] : 'High',
                        'description' => 'Ghost Threat Engine detected malicious payload.',
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
        
        // 2.55 PHP Backdoor / Web Shell Pattern Detection (Free Feature)
        if ( pathinfo( $file_path, PATHINFO_EXTENSION ) === 'php' ) {
            $backdoor_findings = $this->analyze_php_backdoor_patterns( $content );
            if ( ! empty( $backdoor_findings ) ) {
                $findings = array_merge( $findings, $backdoor_findings );
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
                    if ( preg_match( $data['pattern'], $content ) ) {
                        $findings[] = [
                            'pattern'     => 'Regex Match: ' . $key,
                            'risk'        => $data['risk'],
                            'description' => 'File matched known cloud malware signature.',
                            'confidence'  => 95,
                            'line_number' => 0
                        ];
                    }
                }
            }
        }

        // 4. Shannon Entropy Heuristics (Detect heavily obfuscated/encrypted 0-day malware)
        $ext = pathinfo( $file_path, PATHINFO_EXTENSION );
        if ( $ext === 'php' || $ext === 'js' ) {
            $entropy = $this->calculate_entropy( $content );
            // Normal PHP/JS files are around 3.5 - 4.5. Encrypted payloads often exceed 6.0.
            // Core files like class-ftp.php can hit ~5.6 due to dense logic and mixed strings.
            // Highly minified JS can hit 5.8, but > 6.0 is usually malicious packing.
            if ( $entropy > 6.0 ) {
                $findings[] = [
                    'pattern'     => 'high_entropy_' . $ext . ': ' . round( $entropy, 2 ),
                    'risk'        => 'High',
                    'description' => 'Unusually high mathematical entropy detected. This indicates heavy obfuscation or encryption typical of 0-day malware.',
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

        // VirusTotal Cloud Scan
        if ( ! empty( $findings ) && pathinfo( $file_path, PATHINFO_EXTENSION ) === 'php' ) {
            $vt_finding = $this->check_virustotal( $file_path );
            if ( $vt_finding ) {
                $findings[] = $vt_finding;
            }
        }

        // Allow Pro Plugin to run Advanced Malware Detection (AMD) - YARA, Machine Learning, Threat Feeds
        $findings = apply_filters( 'nexura_pro_advanced_scan', $findings, $file_path, $content );

        return $findings;
    }

    /**
     * Checks file hash against VirusTotal API.
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
                        'pattern'     => 'VirusTotal Cloud Match (' . $malicious . ' engines)',
                        'risk'        => 'High',
                        'description' => 'File matches known malware signature on VirusTotal.',
                        'confidence'  => 100,
                        'line_number' => 0
                    ];
                }
            }
        }
        return false;
    }

    /**
     * Analyzes PHP code using tokens to detect obfuscated malware and variable functions.
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
        
        // Suppress errors for invalid syntax in malware
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
                                'description' => 'Suspicious dynamic variable execution (' . $token[1] . '()) detected. This is highly indicative of obfuscated backdoors.',
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
                    'pattern'     => 'eval_execution',
                    'risk'        => 'High',
                    'description' => 'Direct use of eval() detected, commonly used in malicious payloads.',
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
                        // High confidence if it's execution related, lower if it's just base64_decode
                        $is_exec = in_array( $func_name, [ 'system', 'shell_exec', 'passthru', 'exec', 'popen', 'proc_open' ], true );
                        
                        // We lower confidence slightly if it's just base64_decode, as legitimate plugins use it.
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
     * Detects PHP backdoor / web shell patterns.
     * These are common in real-world hacked WordPress sites.
     *
     * @param string $content Raw PHP content.
     * @return array Array of findings.
     */
    private function analyze_php_backdoor_patterns( $content ) {
        $findings = [];

        // Quick skip for performance: if none of these superglobals or preg_replace are present, no backdoors of these types exist.
        if ( stripos( $content, '$_POST' ) === false && 
             stripos( $content, '$_GET' ) === false && 
             stripos( $content, '$_REQUEST' ) === false && 
             stripos( $content, '$_COOKIE' ) === false && 
             stripos( $content, 'preg_replace' ) === false ) {
            return $findings;
        }

        $backdoor_sigs = [
            'shell_exec_post_get' => [
                'pattern'     => '/shell_exec\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/i',
                'description' => 'shell_exec() called with user-supplied input ($_POST/$_GET) — classic web shell backdoor.',
                'risk'        => 'Critical',
                'confidence'  => 99
            ],
            'system_post_get' => [
                'pattern'     => '/system\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/i',
                'description' => 'system() called with user-supplied input — command injection backdoor.',
                'risk'        => 'Critical',
                'confidence'  => 99
            ],
            'passthru_post_get' => [
                'pattern'     => '/passthru\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/i',
                'description' => 'passthru() called with user-supplied input — command execution backdoor.',
                'risk'        => 'Critical',
                'confidence'  => 99
            ],
            'exec_post_get' => [
                'pattern'     => '/\bexec\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/i',
                'description' => 'exec() called with user-supplied input — command execution backdoor.',
                'risk'        => 'Critical',
                'confidence'  => 99
            ],
            'popen_post_get' => [
                'pattern'     => '/popen\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/i',
                'description' => 'popen() called with user-supplied input — process execution backdoor.',
                'risk'        => 'Critical',
                'confidence'  => 99
            ],
            'auth_key_backdoor' => [
                'pattern'     => '/\$_(POST|GET|REQUEST|COOKIE)\s*\[\s*[\'"](key|cmd|pass|password|auth|token|secret|backdoor)[\'"]\s*\].*(?:shell_exec|system|passthru|exec|popen|proc_open)\s*\(/is',
                'description' => 'Auth-key gated backdoor detected — attacker sends secret key to execute commands.',
                'risk'        => 'Critical',
                'confidence'  => 99
            ],
            'reverse_auth_backdoor' => [
                'pattern'     => '/(?:shell_exec|system|passthru|exec|popen|proc_open)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[\s*[\'"](cmd|command|c|x|exec|run)[\'"]\s*\]/i',
                'description' => 'Direct command execution from user input — web shell RAT detected.',
                'risk'        => 'Critical',
                'confidence'  => 99
            ],
            'eval_post_request' => [
                'pattern'     => '/eval\s*\(\s*(?:base64_decode\s*\(\s*)?\$_(POST|GET|REQUEST|COOKIE)\s*\[/i',
                'description' => 'eval() with user-supplied input — arbitrary code execution backdoor.',
                'risk'        => 'Critical',
                'confidence'  => 99
            ],
            'preg_replace_eval' => [
                'pattern'     => '/preg_replace\s*\(\s*[\'"]\/.*\/e[\'"]\s*,/i',
                'description' => 'preg_replace with /e modifier — allows arbitrary code execution (deprecated but still dangerous).',
                'risk'        => 'Critical',
                'confidence'  => 95
            ],
            'file_put_contents_php' => [
                'pattern'     => '/file_put_contents\s*\(\s*.*\$_(POST|GET|REQUEST|COOKIE)/i',
                'description' => 'file_put_contents with user input — file upload/write backdoor.',
                'risk'        => 'Critical',
                'confidence'  => 95
            ],
            'base64_superglobal_combo' => [
                'pattern'     => '/base64_decode\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SERVER)\s*\[/i',
                'description' => 'base64_decode with superglobal input — obfuscated command injection.',
                'risk'        => 'High',
                'confidence'  => 95
            ],
            'hidden_post_cmd_pattern' => [
                'pattern'     => '/if\s*\(\s*isset\s*\(\s*\$_POST\s*\[\s*[\'"](cmd|command|c|x|exec|run|shell)[\'"]\s*\]\s*\)/i',
                'description' => 'Hidden POST command handler detected — typical web shell entry point.',
                'risk'        => 'Critical',
                'confidence'  => 98
            ],
        ];

        foreach ( $backdoor_sigs as $key => $sig ) {
            if ( preg_match( $sig['pattern'], $content ) ) {
                $findings[] = [
                    'pattern'     => 'php_backdoor_' . $key,
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
     * Analyzes JS code for obfuscated malware signatures.
     * 
     * @param string $content Raw JS content.
     * @return array Array of findings.
     */
    private function analyze_js_content( $content ) {
        $findings = [];
        
        $js_signatures = [
            'obfuscated_eval_fromcharcode' => [
                'pattern'     => '/eval\s*\(\s*String\.fromCharCode\s*\(/i',
                'description' => 'Obfuscated JavaScript execution using String.fromCharCode.',
                'risk'        => 'High',
                'confidence'  => 95
            ],
            'obfuscated_document_write_unescape' => [
                'pattern'     => '/document\.write\s*\(\s*unescape\s*\(/i',
                'description' => 'Suspicious document.write combined with unescape, often used to inject malicious iframes.',
                'risk'        => 'Medium',
                'confidence'  => 85
            ],
            'crypto_miner_coinhive' => [
                'pattern'     => '/coinhive\.min\.js|CoinHive\.Anonymous/i',
                'description' => 'CoinHive or similar crypto-miner detected.',
                'risk'        => 'High',
                'confidence'  => 100
            ],
            'crypto_miner_monero' => [
                'pattern'     => '/c-hive\.com|authedmine\.com|minero\.cc/i',
                'description' => 'Known Crypto-miner domain detected.',
                'risk'        => 'High',
                'confidence'  => 100
            ],
            'malicious_iframe_injection' => [
                'pattern'     => '/document\.createElement\s*\(\s*[\'"](iframe)[\'"]\s*\).*(?:src|html)\s*=\s*[\'"](http)/is',
                'description' => 'Suspicious dynamic iframe creation pointing to external URL.',
                'risk'        => 'Medium',
                'confidence'  => 70
            ],
            // ─── Trojan / RAT / Dropper Signatures ───
            'activex_wscript_shell' => [
                'pattern'     => '/new\s+ActiveXObject\s*\(\s*[\'"]WScript\.Shell[\'"]/i',
                'description' => 'ActiveXObject WScript.Shell detected — Windows command execution trojan.',
                'risk'        => 'Critical',
                'confidence'  => 99
            ],
            'activex_adodb_stream' => [
                'pattern'     => '/new\s+ActiveXObject\s*\(\s*[\'"]ADODB\.Stream[\'"]/i',
                'description' => 'ActiveXObject ADODB.Stream detected — binary file download/dropper payload.',
                'risk'        => 'Critical',
                'confidence'  => 99
            ],
            'activex_scripting_fso' => [
                'pattern'     => '/new\s+ActiveXObject\s*\(\s*[\'"]Scripting\.FileSystemObject[\'"]/i',
                'description' => 'ActiveXObject Scripting.FileSystemObject — filesystem access trojan.',
                'risk'        => 'Critical',
                'confidence'  => 99
            ],
            'activex_xmlhttp' => [
                'pattern'     => '/new\s+ActiveXObject\s*\(\s*[\'"]MSXML2\.XMLHTTP[\'"]/i',
                'description' => 'ActiveXObject MSXML2.XMLHTTP — remote payload downloader.',
                'risk'        => 'High',
                'confidence'  => 95
            ],
            'js_saveto_file' => [
                'pattern'     => '/SaveToFile\s*\(/i',
                'description' => 'JavaScript SaveToFile call detected — used by droppers to write executables to disk.',
                'risk'        => 'Critical',
                'confidence'  => 98
            ],
            'js_shellobj_run' => [
                'pattern'     => '/shellObj\.Run\s*\(/i',
                'description' => 'WScript Shell.Run detected — stealthy process execution.',
                'risk'        => 'Critical',
                'confidence'  => 99
            ],
            // ─── Advanced JS Heuristics (Score Boost 8.5 -> 9.2) ───
            'js_suspicious_eval' => [
                'pattern'     => '/eval\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode|\[)/i',
                'description' => 'Suspicious eval() execution with encoded payload. Common in JS malware.',
                'risk'        => 'High',
                'confidence'  => 92
            ],
            'js_new_function_payload' => [
                'pattern'     => '/new\s+Function\s*\(\s*(?:[a-zA-Z0-9_$]+)?\s*(?:,|.)*?\s*(?:atob|unescape)/i',
                'description' => 'Dynamic function generation with encoded body. Often used to bypass WAFs.',
                'risk'        => 'High',
                'confidence'  => 90
            ],
            'js_document_write_script' => [
                'pattern'     => '/document\.write\s*\(\s*[\'"]<script/i',
                'description' => 'document.write() injecting a raw <script> tag. Legacy dropper technique.',
                'risk'        => 'Medium',
                'confidence'  => 80
            ]
        ];

        foreach ( $js_signatures as $key => $sig ) {
            if ( preg_match( $sig['pattern'], $content ) ) {
                $findings[] = [
                    'pattern'     => 'js_malware_' . $key,
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

        $total_items = (int) $wpdb->get_var( "SELECT COUNT(id) FROM {$wpdb->prefix}NEXURA_scan_results" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
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
     * Calculates the Shannon entropy of a string to detect encrypted/obfuscated malware.
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

}
