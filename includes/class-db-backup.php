<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class DB_Backup
 * 
 * High-Performance Streaming & Chunked Database Backup Engine.
 * Streams DDL/DML directly to disk in 1,000 row chunks to prevent PHP memory exhaustion on large WooCommerce sites.
 */
class DB_Backup {

    public function init() {
        add_action( 'wp_ajax_NEXURA_backup_db', [ $this, 'ajax_backup_db' ] );
        add_action( 'wp_ajax_NEXURA_download_backup', [ $this, 'ajax_download_backup' ] );
    }

    /**
     * Creates a chunked, streamed database backup with optional GZIP compression.
     *
     * @return string|false File path on success, false on failure.
     */
    public function create_backup() {
        global $wpdb;

        if ( function_exists( 'set_time_limit' ) ) {
            @set_time_limit( 600 );
        }
        if ( function_exists( 'wp_raise_memory_limit' ) ) {
            @wp_raise_memory_limit( 'admin' );
        }

        $backup_dir = wp_upload_dir()['basedir'] . '/nexura-backups';
        if ( ! file_exists( $backup_dir ) ) {
            wp_mkdir_p( $backup_dir );
            // Protect directory
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_file_put_contents
            file_put_contents( $backup_dir . '/.htaccess', "Order deny,allow\nDeny from all\n<FilesMatch \"\\.(sql|gz)$\">\nDeny from all\n</FilesMatch>" );
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_file_put_contents
            file_put_contents( $backup_dir . '/index.php', '<?php // Silence' );
            file_put_contents( $backup_dir . '/index.html', '' );
        }

        $use_gzip = extension_loaded( 'zlib' );
        $extension = $use_gzip ? '.sql.gz' : '.sql';
        $filename = 'backup_' . gmdate( 'Y-m-d_H-i-s' ) . '_' . wp_generate_password( 32, false ) . $extension;
        $filepath = $backup_dir . '/' . $filename;

        $fp = $use_gzip ? gzopen( $filepath, 'w9' ) : fopen( $filepath, 'w' );
        if ( ! $fp ) {
            return false;
        }

        $write_data = function( $data ) use ( $fp, $use_gzip ) {
            if ( $use_gzip ) {
                gzwrite( $fp, $data );
            } else {
                fwrite( $fp, $data );
            }
        };

        $header = "-- Nexura Security High-Performance Database Backup\n";
        $header .= "-- Time: " . wp_date( 'Y-m-d H:i:s' ) . "\n";
        $header .= "-- Site: " . home_url() . "\n";
        $header .= "-- Engine: Chunked Stream Exporter\n\n";
        $header .= "SET FOREIGN_KEY_CHECKS=0;\n";
        $header .= "SET SQL_MODE = \"NO_AUTO_VALUE_ON_ZERO\";\n\n";
        $write_data( $header );

        $tables = $wpdb->get_results( 'SHOW TABLES', ARRAY_N ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery

        foreach ( $tables as $table ) {
            $raw_table = $table[0];
            
            // SECURITY FIX: Sanitize table name — allow only alphanumerics and underscore
            $table_name = preg_replace( '/[^a-zA-Z0-9_]/', '', $raw_table );
            
            // Only backup tables matching site prefix to prevent database pollution
            if ( strpos( $table_name, $wpdb->prefix ) !== 0 ) continue;

            $create_table = $wpdb->get_row( "SHOW CREATE TABLE `{$table_name}`", ARRAY_N ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange
            if ( ! empty( $create_table[1] ) ) {
                $table_sql = "DROP TABLE IF EXISTS `{$table_name}`;\n";
                $table_sql .= $create_table[1] . ";\n\n";
                $write_data( $table_sql );
            }

            // Chunk rows in batches of 1,000 to keep memory footprint under 10MB
            $count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM `{$table_name}`" ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
            $chunk_size = 1000;

            for ( $offset = 0; $offset < $count; $offset += $chunk_size ) {
                $rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM `{$table_name}` LIMIT %d OFFSET %d", $chunk_size, $offset ), ARRAY_A ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
                if ( empty( $rows ) ) {
                    break;
                }

                $insert_buffer = '';
                foreach ( $rows as $row ) {
                    $escaped_values = array_map( function( $val ) use ( $wpdb ) {
                        if ( is_null( $val ) ) {
                            return 'NULL';
                        }
                        return "'" . $wpdb->_real_escape( $val ) . "'";
                    }, array_values( $row ) );

                    $insert_buffer .= "INSERT INTO `{$table_name}` VALUES (" . implode( ',', $escaped_values ) . ");\n";
                }

                $write_data( $insert_buffer );
                unset( $rows, $insert_buffer );
            }

            $write_data( "\n" );
        }

        $footer = "SET FOREIGN_KEY_CHECKS=1;\n";
        $write_data( $footer );

        if ( $use_gzip ) {
            gzclose( $fp );
        } else {
            fclose( $fp );
        }

        return $filepath;
    }

    public function ajax_backup_db() {
        if ( ! \Nexura_Security::can_manage_security() ) {
            wp_send_json_error( 'Unauthorized' );
        }
        check_ajax_referer( 'nexura_db_backup', '_wpnonce' );
        
        $filepath = $this->create_backup();
        if ( $filepath && file_exists( $filepath ) ) {
            wp_send_json_success( [ 'message' => 'Database backed up successfully.', 'file' => basename( $filepath ) ] );
        } else {
            wp_send_json_error( 'Failed to create database backup.' );
        }
    }

    public function ajax_download_backup() {
        if ( ! \Nexura_Security::can_manage_security() ) {
            wp_die( 'Unauthorized' );
        }

        if ( ! isset( $_GET['_wpnonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ), 'nexura_db_backup' ) ) {
            wp_die( 'Security check failed.' );
        }

        if ( empty( $_GET['file'] ) ) {
            wp_die( 'No file specified' );
        }

        $file = basename( sanitize_text_field( wp_unslash( $_GET['file'] ) ) );
        $backup_dir = wp_upload_dir()['basedir'] . '/nexura-backups';
        $filepath = $backup_dir . '/' . $file;

        $real_backup_dir = realpath( $backup_dir );
        $real_filepath   = realpath( $filepath );

        // Strict Path Traversal Defense: Ensure file resides inside nexura-backups
        if ( ! $real_filepath || ! $real_backup_dir || strpos( $real_filepath, $real_backup_dir ) !== 0 ) {
            wp_die( 'Invalid file path or access denied.' );
        }

        $ext = pathinfo( $real_filepath, PATHINFO_EXTENSION );
        if ( file_exists( $real_filepath ) && is_readable( $real_filepath ) && ( $ext === 'sql' || $ext === 'gz' ) ) {
            $content_type = ( $ext === 'gz' ) ? 'application/gzip' : 'application/sql';

            // Clean any active output buffers to prevent output corruption
            while ( ob_get_level() ) {
                ob_end_clean();
            }

            header( 'Content-Description: File Transfer' );
            header( 'Content-Type: ' . $content_type );
            header( 'Content-Disposition: attachment; filename="' . basename( $real_filepath ) . '"' );
            header( 'Expires: 0' );
            header( 'Cache-Control: must-revalidate' );
            header( 'Pragma: public' );
            header( 'Content-Length: ' . filesize( $real_filepath ) );
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile
            readfile( $real_filepath );
            
            // Delete file after download to save disk space and enhance security
            wp_delete_file( $real_filepath );
            exit;
        } else {
            wp_die( 'File not found or invalid' );
        }
    }
}
