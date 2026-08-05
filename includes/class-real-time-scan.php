<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Real_Time_Scan
 * 
 * Handles event-driven malware scanning for real-time protection.
 */
class Real_Time_Scan {

    private $scanner;

    public function __construct() {
        $this->scanner = new Scanner();

        // Hook into file uploads
        add_filter( 'wp_handle_upload', [ $this, 'scan_uploaded_file' ] );
        
        // Hook into plugin/theme updates or installs
        add_action( 'upgrader_process_complete', [ $this, 'scan_after_upgrade' ], 10, 2 );

        // Hook into content changes
        add_action( 'save_post', [ $this, 'scan_post_content' ], 10, 3 );
        add_action( 'updated_option', [ $this, 'scan_option_value' ], 10, 3 );
        add_action( 'added_option', [ $this, 'scan_option_value' ], 10, 2 );
        add_action( 'user_register', [ $this, 'scan_user_data' ] );
        add_action( 'profile_update', [ $this, 'scan_user_data' ] );
    }

    /**
     * Scans an uploaded file and blocks it if malware or executable PHP/Script tags are found.
     */
    public function scan_uploaded_file( $file ) {
        if ( isset( $file['file'] ) ) {
            $file_path = $file['file'];
            
            if ( ! file_exists( $file_path ) ) {
                return $file;
            }

            // 1. Polyglot Check: Check if image/media file contains executable PHP code or script tags
            $ext = strtolower( pathinfo( $file_path, PATHINFO_EXTENSION ) );
            $media_exts = [ 'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'mp3', 'mp4', 'pdf' ];
            
            if ( in_array( $ext, $media_exts, true ) ) {
                $content = @file_get_contents( $file_path );
                if ( $content !== false ) {
                    if ( strpos( $content, '<?php' ) !== false || strpos( $content, '<?=' ) !== false || stripos( $content, '<script' ) !== false ) {
                        wp_delete_file( $file_path ); // Physically remove the file to prevent execution
                        return [ 'error' => esc_html__( 'Nexura Shield: Upload blocked. Executable PHP/Script tags detected inside media file.', 'nexura-security' ) ];
                    }
                }
            }

            // 2. Standard Malware Signature Scanning
            $findings = $this->scanner->scan_file( $file_path );
            if ( ! empty( $findings ) ) {
                $this->save_findings( $file_path, $findings );
                wp_delete_file( $file_path ); // Physically remove the file to prevent execution
                return [ 'error' => esc_html__( 'Nexura Shield: Malicious pattern detected! Upload has been blocked.', 'nexura-security' ) ];
            }
        }
        return $file;
    }

    /**
     * Scans files extracted during plugin/theme upgrades.
     */
    public function scan_after_upgrade( $upgrader_object, $options ) {
        // If a plugin/theme is updated or installed, we init a background scan.
        if ( isset( $options['action'] ) && in_array( $options['action'], [ 'update', 'install' ] ) ) {
            $this->scanner->init_scan();
        }
    }

    /**
     * Scans post content upon saving.
     */
    public function scan_post_content( $post_id, $post, $update ) {
        if ( wp_is_post_revision( $post_id ) ) {
            return;
        }

        $findings = $this->scan_string( $post->post_content );
        if ( ! empty( $findings ) ) {
            $this->save_findings( 'post_id:' . $post_id, $findings );
        }
    }

    /**
     * Scans an option value.
     */
    public function scan_option_value( $option, $old_value = '', $value = '' ) {
        // Skip scanning Nexura settings to avoid recursion/heavy loops
        if ( strpos( $option, 'NEXURA_' ) === 0 || strpos( $option, 'nexura_' ) === 0 ) {
            return;
        }

        // Skip transient options, cron, rewrite rules, active plugins, etc.
        $ignore_prefixes = [
            '_transient_',
            'transient_',
            'cron',
            'action_scheduler_',
            'wp_user_roles',
            'rewrite_rules',
            'active_plugins',
            'uninstall_plugins',
            'recently_activated',
            'widget_text',
            'sidebars_widgets'
        ];

        foreach ( $ignore_prefixes as $prefix ) {
            if ( strpos( $option, $prefix ) === 0 ) {
                return;
            }
        }

        // If called from added_option, it passes ($option, $value)
        if ( func_num_args() === 2 ) {
            $value = $old_value;
        }

        if ( is_string( $value ) && ! empty( $value ) ) {
            $findings = $this->scan_string( $value );
            if ( ! empty( $findings ) ) {
                $this->save_findings( 'option:' . $option, $findings );
            }
        }
    }

    /**
     * Scans user data.
     */
    public function scan_user_data( $user_id ) {
        $user = get_userdata( $user_id );
        if ( $user ) {
            $findings = $this->scan_string( $user->description . ' ' . $user->user_url );
            if ( ! empty( $findings ) ) {
                $this->save_findings( 'user_id:' . $user_id, $findings );
            }
        }
    }

    /**
     * Helper to scan a raw string using the Scanner's patterns.
     */
    private function scan_string( $content ) {
        $signatures = new Malware_Signatures();
        $patterns = $signatures->get_malware_patterns();
        $findings = [];

        foreach ( $patterns as $key => $data ) {
            if ( isset( $data['pattern'] ) && preg_match( $data['pattern'], $content ) ) {
                $findings[] = [
                    'pattern'     => $key,
                    'risk'        => $data['risk'],
                    'description' => $data['description'],
                    'confidence'  => 100,
                    'line_number' => 0
                ];
            }
        }
        return $findings;
    }

    /**
     * Saves findings to the database.
     */
    private function save_findings( $source, $findings ) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'NEXURA_scan_results';

        foreach ( $findings as $finding ) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery
            $wpdb->insert(
                $table_name,
                [
                    'file_path'   => sanitize_text_field( $source ),
                    'pattern'     => sanitize_text_field( $finding['pattern'] ),
                    'risk_score'  => sanitize_text_field( $finding['risk'] ),
                    'confidence'  => (int) $finding['confidence'],
                    'line_number' => isset( $finding['line_number'] ) ? (int) $finding['line_number'] : 0,
                    'scan_time'   => current_time( 'mysql' )
                ],
                [ '%s', '%s', '%s', '%d', '%d', '%s' ]
            );
        }

        if ( class_exists( '\Nexura_Security\Logger' ) ) {
            Logger::log( 'Real-Time Scan detected malware in: ' . $source );
        }

        // Send instant security alert
        Alert_System::send_alert(
            'Real-Time Scan: Malware Detected',
            sprintf( 'Nexura Security detected %d malicious pattern(s) in: %s. This was caught by the real-time file monitor.', count( $findings ), $source ),
            'high'
        );
    }
}
