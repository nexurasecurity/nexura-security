<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Reinfection_Remediator
 * 
 * Cleans up found persistence mechanisms (Quarantines files, cleans DB/Cron).
 */
class Reinfection_Remediator {

    /**
     * Remediate a specific finding.
     * 
     * @param array $finding The finding data array.
     * @return array Result of the remediation.
     */
    public function remediate( $finding ) {
        if ( ! isset( $finding['type'] ) ) {
            return [ 'success' => false, 'message' => 'Invalid finding format.' ];
        }

        switch ( $finding['type'] ) {
            case 'mu_plugin':
            case 'drop_in':
            case 'uploads_php':
            case 'root_php':
            case 'root_script':    // .py / .js / .sh / .pl scripts in WordPress root
            case 'malware':
            case 'file_reference': // File that references the target
            case 'file_writer':    // File with write/download capabilities
            case 'temp_php':       // PHP in /tmp
            case 'server_log':     // Found in server logs (informational only)
                return $this->quarantine_file( $finding['path'] );

            case 'html_defacement': // Defacement HTML/HTM file in root — direct delete (no quarantine needed)
                return $this->delete_defacement_file( $finding['path'] );

            case 'wp_cron':
                return $this->remove_cron( $finding['hook'] );

            case 'db_payload':
                return $this->remove_db_option( $finding['option'] );

            case 'db_trigger':
                return $this->remove_db_trigger( $finding['option'] ); // 'option' holds trigger name

            case 'config_injection':
            case 'php_fpm_injection':
                return $this->clean_config( $finding['path'] );

            default:
                return [ 'success' => false, 'message' => 'Unknown finding type: ' . sanitize_text_field( $finding['type'] ) ];
        }
    }

    /**
     * Quarantine a file.
     * Also adds .htaccess PHP execution block if the file was in uploads.
     */
    private function quarantine_file( $path ) {
        if ( ! file_exists( $path ) ) {
            return [ 'success' => false, 'message' => 'File not found.' ];
        }

        if ( ! class_exists( '\Nexura_Security\Quarantine' ) ) {
            return [ 'success' => false, 'message' => 'Quarantine module not available.' ];
        }

        $quarantine = new Quarantine();
        $result = $quarantine->quarantine_file( $path );

        if ( $result && ! is_wp_error( $result ) ) {
            // If the file was in the uploads directory, add .htaccess protection
            $upload_dir = wp_upload_dir();
            if ( strpos( realpath( dirname( $path ) ), realpath( $upload_dir['basedir'] ) ) === 0 ) {
                $this->protect_uploads_dir( dirname( $path ) );
            }
            return [ 'success' => true, 'message' => 'File successfully quarantined.' ];
        }

        return [ 'success' => false, 'message' => 'Failed to quarantine file.' ];
    }

    /**
     * Write a .htaccess file to block PHP execution in a given directory.
     *
     * @param string $dir Absolute directory path.
     */
    private function protect_uploads_dir( $dir ) {
        $htaccess = trailingslashit( $dir ) . '.htaccess';
        if ( file_exists( $htaccess ) ) return; // Don't overwrite existing

        $rules = "# Nexura Security — Block PHP Execution\n" .
                 "<FilesMatch \"\\.(?:php|phtml|php3|php4|php5|php7|php8)$\">\n" .
                 "    Require all denied\n" .
                 "</FilesMatch>\n";

        file_put_contents( $htaccess, $rules, LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions
    }

    /**
     * Remove a suspicious cron job.
     */
    private function remove_cron( $hook ) {
        if ( empty( $hook ) ) {
            return [ 'success' => false, 'message' => 'Invalid hook name.' ];
        }
        wp_clear_scheduled_hook( $hook );
        return [ 'success' => true, 'message' => "Cron hook '{$hook}' removed." ];
    }

    /**
     * Remove a malicious DB option.
     */
    private function remove_db_option( $option_name ) {
        if ( empty( $option_name ) ) {
            return [ 'success' => false, 'message' => 'Invalid option name.' ];
        }
        delete_option( $option_name );
        return [ 'success' => true, 'message' => "Database option '{$option_name}' removed." ];
    }

    /**
     * Clean config file (basic auto_prepend_file removal).
     */
    private function clean_config( $path ) {
        if ( ! file_exists( $path ) ) {
            return [ 'success' => false, 'message' => 'Config file not found.' ];
        }

        $content = file_get_contents( $path );
        // Basic naive removal of php_value auto_prepend_file line
        $clean_content = preg_replace( '/php_value\s+auto_prepend_file\s+[^\r\n]+/i', '', $content );
        $clean_content = preg_replace( '/auto_prepend_file\s*=\s*[^\r\n]+/i', '', $clean_content );

        if ( $content !== $clean_content ) {
            if ( file_put_contents( $path, $clean_content ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
                return [ 'success' => true, 'message' => 'Config file cleaned.' ];
            }
            return [ 'success' => false, 'message' => 'Failed to write cleaned config.' ];
        }

        return [ 'success' => true, 'message' => 'No known injection matched for automatic removal. Manual review needed.' ];
    }

    /**
     * Drop a malicious MySQL TRIGGER from the database.
     *
     * @param string $trigger_name Name of the DB trigger to remove.
     * @return array
     */
    private function remove_db_trigger( $trigger_name ) {
        if ( empty( $trigger_name ) ) {
            return [ 'success' => false, 'message' => 'Invalid trigger name.' ];
        }

        global $wpdb;

        // Sanitize: only allow alphanumeric and underscore for trigger names
        $safe_name = preg_replace( '/[^a-zA-Z0-9_]/', '', $trigger_name );
        if ( $safe_name !== $trigger_name ) {
            return [ 'success' => false, 'message' => 'Trigger name contains invalid characters.' ];
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $result = $wpdb->query( "DROP TRIGGER IF EXISTS `{$safe_name}`" );

        if ( $result !== false ) {
            return [ 'success' => true, 'message' => "MySQL trigger '{$safe_name}' dropped successfully." ];
        }

        return [ 'success' => false, 'message' => "Failed to drop trigger '{$safe_name}'." ];
    }

    /**
     * Delete an HTML/HTM defacement file from the WordPress root.
     * These files don't require quarantine — they are non-executable defacement pages
     * and can be safely deleted by free users.
     *
     * @param string $path Absolute path to the defacement file.
     * @return array
     */
    private function delete_defacement_file( $path ) {
        if ( empty( $path ) ) {
            return [ 'success' => false, 'message' => 'No file path provided.' ];
        }

        $path = realpath( $path );

        if ( ! $path || ! file_exists( $path ) ) {
            return [ 'success' => false, 'message' => 'Defacement file not found (may have already been deleted).' ];
        }

        // Security: only allow deletion of .html/.htm files in WordPress root
        $abspath = rtrim( realpath( ABSPATH ), '/\\' );
        $file_dir = rtrim( dirname( $path ), '/\\' );

        if ( $file_dir !== $abspath ) {
            return [ 'success' => false, 'message' => 'Security check failed: file is not in WordPress root directory.' ];
        }

        $ext = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
        if ( ! in_array( $ext, [ 'html', 'htm' ], true ) ) {
            return [ 'success' => false, 'message' => 'Security check failed: not an HTML/HTM file.' ];
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
        if ( @unlink( $path ) ) {
            return [ 'success' => true, 'message' => 'Defacement file deleted successfully: ' . basename( $path ) ];
        }

        return [ 'success' => false, 'message' => 'Failed to delete defacement file. Check file permissions.' ];
    }
}


