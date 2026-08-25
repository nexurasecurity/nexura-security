<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Safe_Cleanup
 * 
 * Handles quarantining, backing up, cleaning, and rolling back infected files.
 */
class Safe_Cleanup {

    private $quarantine_dir;
    private $backup_dir;

    public function __construct() {
        $upload_dir = wp_upload_dir();
        $this->quarantine_dir = trailingslashit( $upload_dir['basedir'] ) . 'nexura-security/quarantine/';
        $this->backup_dir     = trailingslashit( $upload_dir['basedir'] ) . 'nexura-security/backups/';
        $this->ensure_dirs();
    }

    private function ensure_dirs() {
        require_once ABSPATH . 'wp-admin/includes/file.php';
        WP_Filesystem();
        global $wp_filesystem;

        $dirs = [ $this->quarantine_dir, $this->backup_dir ];
        foreach ( $dirs as $dir ) {
            if ( ! $wp_filesystem->is_dir( $dir ) ) {
                wp_mkdir_p( $dir );
                $wp_filesystem->put_contents( $dir . '.htaccess', "Deny from all\n" );
                $wp_filesystem->put_contents( $dir . 'index.php', "<?php\n// Silence is golden.\n" );
            }
        }
    }

    /**
     * Backups a file before modifying it.
     */
    public function backup_file( $file_path ) {
        if ( ! file_exists( $file_path ) ) {
            return new \WP_Error( 'file_missing', 'File does not exist.' );
        }

        global $wp_filesystem;
        $hash = md5( $file_path . time() );
        $backup_path = $this->backup_dir . basename( $file_path ) . '_' . $hash . '.bak';
        
        if ( $wp_filesystem->copy( $file_path, $backup_path, true ) ) {
            // Save metadata about the backup so we know where to restore it
            $meta = [
                'original_path' => $file_path,
                'backup_path'   => $backup_path,
                'timestamp'     => current_time('timestamp')
            ];
            $wp_filesystem->put_contents( $backup_path . '.meta', wp_json_encode( $meta ) );
            return $backup_path;
        }

        return new \WP_Error( 'backup_failed', 'Failed to create backup.' );
    }

    /**
     * Restores a file from backup (Rollback).
     */
    public function rollback_file( $backup_path ) {
        global $wp_filesystem;
        if ( ! $wp_filesystem->exists( $backup_path ) || ! $wp_filesystem->exists( $backup_path . '.meta' ) ) {
            return new \WP_Error( 'backup_missing', 'Backup file or metadata missing.' );
        }

        $meta = json_decode( $wp_filesystem->get_contents( $backup_path . '.meta' ), true );
        if ( ! $meta || empty( $meta['original_path'] ) ) {
            return new \WP_Error( 'meta_corrupt', 'Backup metadata is corrupt.' );
        }

        if ( $wp_filesystem->copy( $backup_path, $meta['original_path'], true ) ) {
            return true;
        }

        return new \WP_Error( 'rollback_failed', 'Failed to restore file.' );
    }

    /**
     * Moves a file to quarantine.
     */
    public function quarantine_file( $file_path ) {
        if ( ! file_exists( $file_path ) ) {
            return new \WP_Error( 'file_missing', 'File does not exist.' );
        }

        global $wp_filesystem;
        $hash = md5( $file_path . time() );
        $quarantine_path = $this->quarantine_dir . basename( $file_path ) . '_' . $hash . '.qtn';

        if ( $wp_filesystem->move( $file_path, $quarantine_path, true ) ) {
            $meta = [
                'original_path'   => $file_path,
                'quarantine_path' => $quarantine_path,
                'timestamp'       => current_time('timestamp')
            ];
            $wp_filesystem->put_contents( $quarantine_path . '.meta', wp_json_encode( $meta ) );
            return $quarantine_path;
        }

        return new \WP_Error( 'quarantine_failed', 'Failed to quarantine file.' );
    }

    /**
     * Attempts to automatically clean a file by stripping malicious patterns.
     */
    public function clean_file( $file_path ) {
        if ( ! file_exists( $file_path ) ) {
            return new \WP_Error( 'file_missing', 'File does not exist.' );
        }

        // Always backup first
        $backup = $this->backup_file( $file_path );
        if ( is_wp_error( $backup ) ) {
            return $backup;
        }

        global $wp_filesystem;
        $content = $wp_filesystem->get_contents( $file_path );

        // Strip common injected malicious payloads
        $patterns = [
            '/<\?php\s+@e'.'val\(\$_POST\[.*?\]\);\s*\?>/is',
            '/<\?php\s+e'.'val\(\$_COOKIE\[.*?\]\);\s*\?>/is',
            '/<\?php\s+sys'.'tem\(\$_GET\[.*?\]\);\s*\?>/is',
            '/<script[^>]*>(?:(?!(<\/script>)).)*?(?:e'.'val\(unescape|e'.'val\(String\.fromCharCode|document\.write\(unescape).*?<\/script>/is'
        ];

        $cleaned_content = preg_replace( $patterns, '', $content );

        if ( $cleaned_content === $content ) {
            // Nothing was removed. The infection might be complex.
            // Move to quarantine instead.
            return $this->quarantine_file( $file_path );
        }

        if ( $wp_filesystem->put_contents( $file_path, $cleaned_content ) ) {
            return true;
        }

        return new \WP_Error( 'clean_failed', 'Failed to write cleaned content to file.' );
    }
}
