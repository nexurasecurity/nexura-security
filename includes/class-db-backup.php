<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class DB_Backup
 *
 * Chunked Database Backup Engine.
 * Uses REST API with per-table steps to prevent PHP timeout on large WooCommerce sites.
 *
 * Flow:
 *   1. POST nexura/v1/backup/init     -> Get table list, write header. Returns session_id.
 *   2. POST nexura/v1/backup/step     -> Write one chunk (500 rows). Returns progress.
 *   3. GET  nexura/v1/backup/download -> Stream file to browser and delete it.
 */
class DB_Backup {

    const CHUNK_SIZE    = 500;
    const TRANSIENT_TTL = 10800; // 3 hours

    public function init() {
        add_action( 'wp_ajax_NEXURA_backup_db',       [ $this, 'ajax_backup_db' ] );
        add_action( 'wp_ajax_NEXURA_download_backup', [ $this, 'ajax_download_backup' ] );
        add_action( 'rest_api_init', [ $this, 'register_rest_routes' ] );
    }

    /* ------------------------------------------------------------------ */
    /*  REST Route Registration                                             */
    /* ------------------------------------------------------------------ */

    public function register_rest_routes() {
        $ns = 'nexura/v1';
        register_rest_route( $ns, '/backup/init', [
            'methods'             => 'POST',
            'callback'            => [ $this, 'rest_init' ],
            'permission_callback' => [ $this, 'check_permission' ],
        ] );
        register_rest_route( $ns, '/backup/step', [
            'methods'             => 'POST',
            'callback'            => [ $this, 'rest_step' ],
            'permission_callback' => [ $this, 'check_permission' ],
        ] );
        register_rest_route( $ns, '/backup/download', [
            'methods'             => 'GET',
            'callback'            => [ $this, 'rest_download' ],
            'permission_callback' => [ $this, 'check_permission' ],
        ] );
    }

    public function check_permission() {
        return \Nexura_Security::can_manage_security();
    }

    /* ------------------------------------------------------------------ */
    /*  REST: Init                                                          */
    /* ------------------------------------------------------------------ */

    public function rest_init( \WP_REST_Request $request ) {
        global $wpdb;
        if ( function_exists( 'set_time_limit' ) ) {
            @set_time_limit( 120 );
        }

        $backup_dir = wp_upload_dir()['basedir'] . '/nexura-backups';
        if ( ! file_exists( $backup_dir ) ) {
            wp_mkdir_p( $backup_dir );
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_file_put_contents
            file_put_contents( $backup_dir . '/.htaccess', "Order deny,allow\nDeny from all\n<FilesMatch \"\\.(sql|gz)$\">\nDeny from all\n</FilesMatch>" );
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_file_put_contents
            file_put_contents( $backup_dir . '/index.php', '<?php // Silence' );
            file_put_contents( $backup_dir . '/index.html', '' );
        }

        $use_gzip = extension_loaded( 'zlib' );
        $filename = 'backup_' . gmdate( 'Y-m-d_H-i-s' ) . '_' . wp_generate_password( 16, false ) . ( $use_gzip ? '.sql.gz' : '.sql' );
        $filepath = $backup_dir . '/' . $filename;

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
        $fp = $use_gzip ? gzopen( $filepath, 'w9' ) : fopen( $filepath, 'w' );
        if ( ! $fp ) {
            return new \WP_REST_Response( [ 'success' => false, 'message' => 'Cannot create backup file.' ], 500 );
        }

        $header  = "-- Nexura Security Chunked Database Backup\n";
        $header .= "-- Date: " . wp_date( 'Y-m-d H:i:s' ) . "\n";
        $header .= "-- Site: " . home_url() . "\n";
        $header .= "-- Engine: Chunked REST Backup (" . self::CHUNK_SIZE . " rows/step)\n\n";
        $header .= "SET FOREIGN_KEY_CHECKS=0;\n";
        $header .= "SET SQL_MODE = \"NO_AUTO_VALUE_ON_ZERO\";\n\n";

        if ( $use_gzip ) {
            gzwrite( $fp, $header );
            gzclose( $fp );
        } else {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite, WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fwrite( $fp, $header ); fclose( $fp );
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $all_tables = $wpdb->get_results( 'SHOW TABLES', ARRAY_N );
        $tables     = [];
        foreach ( $all_tables as $t ) {
            $tname = preg_replace( '/[^a-zA-Z0-9_]/', '', $t[0] );
            if ( strpos( $tname, $wpdb->prefix ) === 0 ) {
                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $count    = (int) $wpdb->get_var( "SELECT COUNT(*) FROM `{$tname}`" );
                $tables[] = [ 'name' => $tname, 'rows' => $count ];
            }
        }

        $total_rows = array_sum( array_column( $tables, 'rows' ) );
        $session_id = wp_generate_password( 32, false );

        set_transient( 'nexura_backup_' . $session_id, [
            'file'           => $filepath,
            'use_gzip'       => $use_gzip,
            'tables'         => $tables,
            'table_index'    => 0,
            'current_offset' => 0,
            'rows_done'      => 0,
            'total_rows'     => $total_rows,
        ], self::TRANSIENT_TTL );

        return new \WP_REST_Response( [
            'success'      => true,
            'session_id'   => $session_id,
            'total_rows'   => $total_rows,
            'total_tables' => count( $tables ),
            'tables'       => array_column( $tables, 'name' ),
        ], 200 );
    }

    /* ------------------------------------------------------------------ */
    /*  REST: Step                                                          */
    /* ------------------------------------------------------------------ */

    public function rest_step( \WP_REST_Request $request ) {
        global $wpdb;
        if ( function_exists( 'set_time_limit' ) ) {
            @set_time_limit( 60 );
        }

        $session_id = sanitize_text_field( $request->get_param( 'session_id' ) );
        if ( ! $session_id ) {
            return new \WP_REST_Response( [ 'success' => false, 'message' => 'Missing session_id' ], 400 );
        }

        $session = get_transient( 'nexura_backup_' . $session_id );
        if ( ! $session ) {
            return new \WP_REST_Response( [ 'success' => false, 'message' => 'Session expired. Please restart backup.' ], 404 );
        }

        $filepath    = $session['file'];
        $use_gzip    = $session['use_gzip'];
        $tables      = $session['tables'];
        $table_index = $session['table_index'];
        $offset      = $session['current_offset'];

        if ( $table_index >= count( $tables ) ) {
            $this->append_to_file( $filepath, $use_gzip, "SET FOREIGN_KEY_CHECKS=1;\n" );
            delete_transient( 'nexura_backup_' . $session_id );
            return new \WP_REST_Response( [
                'success'   => true,
                'done'      => true,
                'file'      => basename( $filepath ),
                'rows_done' => $session['rows_done'],
                'progress'  => 100,
            ], 200 );
        }

        $table_name = $tables[ $table_index ]['name'];

        if ( $offset === 0 ) {
            // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
            $create = $wpdb->get_row( "SHOW CREATE TABLE `{$table_name}`", ARRAY_N );
            if ( ! empty( $create[1] ) ) {
                $ddl  = "-- Table: `{$table_name}` ({$tables[$table_index]['rows']} rows)\n";
                $ddl .= "DROP TABLE IF EXISTS `{$table_name}`;\n";
                $ddl .= $create[1] . ";\n\n";
                $this->append_to_file( $filepath, $use_gzip, $ddl );
            }
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $rows = $wpdb->get_results(
            $wpdb->prepare( "SELECT * FROM `{$table_name}` LIMIT %d OFFSET %d", self::CHUNK_SIZE, $offset ),
            ARRAY_A
        );

        $rows_written = 0;
        if ( ! empty( $rows ) ) {
            $buffer = '';
            foreach ( $rows as $row ) {
                $escaped = array_map(
                    function( $val ) use ( $wpdb ) {
                        return is_null( $val ) ? 'NULL' : "'" . $wpdb->_real_escape( $val ) . "'";
                    },
                    array_values( $row )
                );
                $buffer .= "INSERT INTO `{$table_name}` VALUES (" . implode( ',', $escaped ) . ");\n";
            }
            $this->append_to_file( $filepath, $use_gzip, $buffer );
            $rows_written = count( $rows );
        }

        $new_rows_done = $session['rows_done'] + $rows_written;
        $table_done    = ( $rows_written < self::CHUNK_SIZE );

        if ( $table_done ) {
            $this->append_to_file( $filepath, $use_gzip, "\n" );
            $table_index++;
            $offset = 0;
        } else {
            $offset += self::CHUNK_SIZE;
        }

        $progress = $session['total_rows'] > 0
            ? min( 99, (int) round( ( $new_rows_done / $session['total_rows'] ) * 100 ) )
            : 0;

        $session['table_index']    = $table_index;
        $session['current_offset'] = $offset;
        $session['rows_done']      = $new_rows_done;
        set_transient( 'nexura_backup_' . $session_id, $session, self::TRANSIENT_TTL );

        $current_table = isset( $tables[ $table_index ] ) ? $tables[ $table_index ]['name'] : 'Finalizing...';

        return new \WP_REST_Response( [
            'success'       => true,
            'done'          => false,
            'progress'      => $progress,
            'rows_done'     => $new_rows_done,
            'total_rows'    => $session['total_rows'],
            'table_index'   => $table_index,
            'total_tables'  => count( $tables ),
            'current_table' => $current_table,
        ], 200 );
    }

    /* ------------------------------------------------------------------ */
    /*  REST: Download                                                      */
    /* ------------------------------------------------------------------ */

    public function rest_download( \WP_REST_Request $request ) {
        $file = sanitize_text_field( $request->get_param( 'file' ) );
        if ( ! $file ) {
            return new \WP_REST_Response( [ 'success' => false, 'message' => 'No file specified.' ], 400 );
        }

        $backup_dir    = wp_upload_dir()['basedir'] . '/nexura-backups';
        $filepath      = $backup_dir . '/' . basename( $file );
        $real_backup   = realpath( $backup_dir );
        $real_filepath = realpath( $filepath );

        if ( ! $real_filepath || ! $real_backup || strpos( $real_filepath, $real_backup ) !== 0 ) {
            return new \WP_REST_Response( [ 'success' => false, 'message' => 'Invalid file path.' ], 403 );
        }

        $ext = pathinfo( $real_filepath, PATHINFO_EXTENSION );
        if ( ! file_exists( $real_filepath ) || ! in_array( $ext, [ 'sql', 'gz' ], true ) ) {
            return new \WP_REST_Response( [ 'success' => false, 'message' => 'File not found.' ], 404 );
        }

        while ( ob_get_level() ) {
            ob_end_clean();
        }

        $content_type = ( $ext === 'gz' ) ? 'application/gzip' : 'application/sql';
        header( 'Content-Description: File Transfer' );
        header( 'Content-Type: ' . $content_type );
        header( 'Content-Disposition: attachment; filename="' . basename( $real_filepath ) . '"' );
        header( 'Expires: 0' );
        header( 'Cache-Control: must-revalidate' );
        header( 'Pragma: public' );
        header( 'Content-Length: ' . filesize( $real_filepath ) );
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile
        readfile( $real_filepath );
        wp_delete_file( $real_filepath );
        exit;
    }

    /* ------------------------------------------------------------------ */
    /*  Helper: Append to file                                              */
    /* ------------------------------------------------------------------ */

    private function append_to_file( $filepath, $use_gzip, $data ) {
        if ( $use_gzip ) {
            $fp = gzopen( $filepath, 'a9' );
            if ( $fp ) {
                gzwrite( $fp, $data );
                gzclose( $fp );
            }
        } else {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
            file_put_contents( $filepath, $data, FILE_APPEND );
        }
    }

    /* ------------------------------------------------------------------ */
    /*  Legacy AJAX Handlers                                                */
    /* ------------------------------------------------------------------ */

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

        $file        = basename( sanitize_text_field( wp_unslash( $_GET['file'] ) ) );
        $backup_dir  = wp_upload_dir()['basedir'] . '/nexura-backups';
        $real_backup = realpath( $backup_dir );
        $real_path   = realpath( $backup_dir . '/' . $file );

        if ( ! $real_path || ! $real_backup || strpos( $real_path, $real_backup ) !== 0 ) {
            wp_die( 'Invalid file path or access denied.' );
        }

        $ext = pathinfo( $real_path, PATHINFO_EXTENSION );
        if ( file_exists( $real_path ) && is_readable( $real_path ) && in_array( $ext, [ 'sql', 'gz' ], true ) ) {
            while ( ob_get_level() ) { ob_end_clean(); }
            header( 'Content-Type: ' . ( $ext === 'gz' ? 'application/gzip' : 'application/sql' ) );
            header( 'Content-Disposition: attachment; filename="' . basename( $real_path ) . '"' );
            header( 'Content-Length: ' . filesize( $real_path ) );
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile
            readfile( $real_path );
            wp_delete_file( $real_path );
            exit;
        }
        wp_die( 'File not found or invalid' );
    }

    /* ------------------------------------------------------------------ */
    /*  Legacy: Full single-request backup (small sites / fallback)        */
    /* ------------------------------------------------------------------ */

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
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_file_put_contents
            file_put_contents( $backup_dir . '/.htaccess', "Order deny,allow\nDeny from all\n<FilesMatch \"\\.(sql|gz)$\">\nDeny from all\n</FilesMatch>" );
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_file_put_contents
            file_put_contents( $backup_dir . '/index.php', '<?php // Silence' );
            file_put_contents( $backup_dir . '/index.html', '' );
        }

        $use_gzip = extension_loaded( 'zlib' );
        $filename = 'backup_' . gmdate( 'Y-m-d_H-i-s' ) . '_' . wp_generate_password( 32, false ) . ( $use_gzip ? '.sql.gz' : '.sql' );
        $filepath = $backup_dir . '/' . $filename;

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
        $fp = $use_gzip ? gzopen( $filepath, 'w9' ) : fopen( $filepath, 'w' );
        if ( ! $fp ) {
            return false;
        }

        $write_data = function( $data ) use ( $fp, $use_gzip ) {
            if ( $use_gzip ) {
                gzwrite( $fp, $data );
            } else {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
                fwrite( $fp, $data );
            }
        };

        $header  = "-- Nexura Security High-Performance Database Backup\n";
        $header .= "-- Time: " . wp_date( 'Y-m-d H:i:s' ) . "\n";
        $header .= "-- Site: " . home_url() . "\n";
        $header .= "-- Engine: Chunked Stream Exporter\n\n";
        $header .= "SET FOREIGN_KEY_CHECKS=0;\n";
        $header .= "SET SQL_MODE = \"NO_AUTO_VALUE_ON_ZERO\";\n\n";
        $write_data( $header );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
        $tables = $wpdb->get_results( 'SHOW TABLES', ARRAY_N );

        foreach ( $tables as $table ) {
            $table_name = preg_replace( '/[^a-zA-Z0-9_]/', '', $table[0] );
            if ( strpos( $table_name, $wpdb->prefix ) !== 0 ) {
                continue;
            }

            // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange
            $create_table = $wpdb->get_row( "SHOW CREATE TABLE `{$table_name}`", ARRAY_N );
            if ( ! empty( $create_table[1] ) ) {
                $write_data( "DROP TABLE IF EXISTS `{$table_name}`;\n" . $create_table[1] . ";\n\n" );
            }

            // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
            $count      = (int) $wpdb->get_var( "SELECT COUNT(*) FROM `{$table_name}`" );
            $chunk_size = 1000;

            for ( $offset = 0; $offset < $count; $offset += $chunk_size ) {
                // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
                $rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM `{$table_name}` LIMIT %d OFFSET %d", $chunk_size, $offset ), ARRAY_A );
                if ( empty( $rows ) ) {
                    break;
                }
                $buffer = '';
                foreach ( $rows as $row ) {
                    $escaped_values = array_map(
                        function( $val ) use ( $wpdb ) {
                            if ( is_null( $val ) ) {
                                return 'NULL';
                            }
                            return "'" . $wpdb->_real_escape( $val ) . "'";
                        },
                        array_values( $row )
                    );
                    $buffer .= "INSERT INTO `{$table_name}` VALUES (" . implode( ',', $escaped_values ) . ");\n";
                }
                $write_data( $buffer );
                unset( $rows, $buffer );
            }
            $write_data( "\n" );
        }

        $write_data( "SET FOREIGN_KEY_CHECKS=1;\n" );
        if ( $use_gzip ) {
            gzclose( $fp );
        } else {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose( $fp );
        }
        return $filepath;
    }
}
