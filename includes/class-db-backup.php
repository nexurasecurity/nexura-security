<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class DB_Backup
 * 
 * Simple database backup tool before critical operations.
 */
class DB_Backup {

    public function init() {
        add_action( 'wp_ajax_NEXURA_backup_db', [ $this, 'ajax_backup_db' ] );
        add_action( 'wp_ajax_NEXURA_download_backup', [ $this, 'ajax_download_backup' ] );
    }

    public function create_backup() {
        global $wpdb;

        $backup_dir = wp_upload_dir()['basedir'] . '/nexura-backups';
        if ( ! file_exists( $backup_dir ) ) {
            wp_mkdir_p( $backup_dir );
            // Protect directory
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_file_put_contents
            file_put_contents( $backup_dir . '/.htaccess', "Order deny,allow\nDeny from all" );
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_file_put_contents
            file_put_contents( $backup_dir . '/index.php', '<?php // Silence' );
            file_put_contents( $backup_dir . '/index.html', '' );
        }

        $tables = $wpdb->get_results( 'SHOW TABLES', ARRAY_N ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
        $sql_dump = "-- Nexura Security Database Backup\n";
        $sql_dump .= "-- Time: " . wp_date( 'Y-m-d H:i:s' ) . "\n\n";

        foreach ( $tables as $table ) {
            $raw_table = $table[0];
            
            // SECURITY FIX: Sanitize table name — allow only alphanumerics and underscore
            $table_name = preg_replace( '/[^a-zA-Z0-9_]/', '', $raw_table );
            
            // Only backup core tables and our own tables to save time/space
            if ( strpos( $table_name, $wpdb->prefix ) !== 0 ) continue;

            $create_table = $wpdb->get_row( "SHOW CREATE TABLE {$table_name}", ARRAY_N ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange
            $sql_dump .= "\n\n" . $create_table[1] . ";\n\n";

            // Only backup data for small tables, skip huge ones if needed, 
            // but for a full backup we need everything.
            $rows = $wpdb->get_results( "SELECT * FROM {$table_name}", ARRAY_A ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
            foreach ( $rows as $row ) {
                $values = array_map( [ $wpdb, '_real_escape' ], array_values( $row ) );
                $values = implode( "','", $values );
                $sql_dump .= "INSERT INTO $table_name VALUES ('" . $values . "');\n";
            }
        }

        $filename = 'backup_' . gmdate( 'Y-m-d_H-i-s' ) . '_' . wp_generate_password( 64, false ) . '.sql';
        $filepath = $backup_dir . '/' . $filename;

        file_put_contents( $filepath, $sql_dump ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_file_put_contents
        
        return $filepath;
    }

    public function ajax_backup_db() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Unauthorized' );
        }
        check_ajax_referer( 'nexura_db_backup', '_wpnonce' );
        
        $filepath = $this->create_backup();
        if ( file_exists( $filepath ) ) {
            wp_send_json_success( [ 'message' => 'Database backed up successfully.', 'file' => basename( $filepath ) ] );
        } else {
            wp_send_json_error( 'Failed to create backup.' );
        }
    }

    public function ajax_download_backup() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Unauthorized' );
        }

        if ( ! isset( $_GET['_wpnonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ), 'nexura_db_backup' ) ) {
            wp_die( 'Security check failed.' );
        }

        if ( empty( $_GET['file'] ) ) {
            wp_die( 'No file specified' );
        }

        $file = sanitize_file_name( wp_unslash( $_GET['file'] ) );
        $backup_dir = wp_upload_dir()['basedir'] . '/nexura-backups';
        $filepath = $backup_dir . '/' . $file;

        if ( file_exists( $filepath ) && is_readable( $filepath ) && pathinfo($filepath, PATHINFO_EXTENSION) === 'sql' ) {
            header( 'Content-Description: File Transfer' );
            header( 'Content-Type: application/sql' );
            header( 'Content-Disposition: attachment; filename="' . basename( $filepath ) . '"' );
            header( 'Expires: 0' );
            header( 'Cache-Control: must-revalidate' );
            header( 'Pragma: public' );
            header( 'Content-Length: ' . filesize( $filepath ) );
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile
            readfile( $filepath );
            
            // Delete file after download to save disk space and enhance security
            wp_delete_file( $filepath );
            exit;
        } else {
            wp_die( 'File not found or invalid' );
        }
    }
}
