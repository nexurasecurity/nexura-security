<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Attack_Logger
 * Handles logging of security events and blocked attacks.
 */
class Attack_Logger {

    /**
     * Log a blocked attack or security event.
     *
     * @param string $ip_address The attacker's IP address.
     * @param string $attack_type Description of the attack type.
     * @param string $action_taken The action taken (e.g., 'Blocked', 'Locked Out').
     */
    public static function log_attack( $ip_address, $attack_type, $action_taken ) {
        global $wpdb;

        if ( empty( $ip_address ) ) {
            // Try to get IP if not provided
            $ip_address = self::get_client_ip();
        }

        if ( empty( $ip_address ) ) {
            return;
        }

        $table_name = $wpdb->prefix . 'NEXURA_attack_logs';

        // Check if table exists (in case plugin is not reactivated yet)
        $actual_table = $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table_name ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        if ( ! $actual_table || strcasecmp( $actual_table, $table_name ) !== 0 ) {
            return;
        }

        // We leave country as 'Unknown' by default. The UI will fetch it via JS.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $wpdb->insert(
            $table_name,
            [
                'ip_address'   => sanitize_text_field( $ip_address ),
                'country'      => 'Unknown',
                'attack_type'  => sanitize_text_field( $attack_type ),
                'action_taken' => sanitize_text_field( $action_taken ),
                'timestamp'    => current_time( 'mysql' ),
            ],
            [
                '%s',
                '%s',
                '%s',
                '%s',
                '%s'
            ]
        );

        // Keep table size manageable (e.g., limit to last 500 logs)
        // Cleanup happens randomly to avoid performance hit on every block
        if ( wp_rand( 1, 10 ) === 1 ) {
            self::cleanup_old_logs( $table_name );
        }
    }

    /**
     * Keep only the latest 500 logs.
     */
    private static function cleanup_old_logs( $table_name ) {
        global $wpdb;
        $count = $wpdb->get_var( "SELECT COUNT(id) FROM {$table_name}" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        
        if ( $count > 500 ) {
            // Delete oldest logs, keeping the newest 500
            $offset = 500;
            $wpdb->query( $wpdb->prepare( "DELETE FROM {$table_name} WHERE id NOT IN (SELECT id FROM (SELECT id FROM {$table_name} ORDER BY id DESC LIMIT %d) foo)", $offset ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        }
    }

    /**
     * Get client IP safely.
     */
    public static function get_client_ip() {
        $ip = '';
        if ( isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
            $ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
        } elseif ( isset( $_SERVER['HTTP_X_REAL_IP'] ) ) {
            $ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) );
        } elseif ( isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
            $ips = explode( ',', sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
            $ip  = trim( $ips[0] );
        } elseif ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
            $ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
        }
        return $ip;
    }
}
