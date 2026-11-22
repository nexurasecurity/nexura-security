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
     * Get client IP safely. Only trusts CF-Connecting-IP when REMOTE_ADDR is a verified Cloudflare IP.
     */
    public static function get_client_ip() {
        $remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '127.0.0.1';
        if ( ! filter_var( $remote_addr, FILTER_VALIDATE_IP ) ) {
            return '127.0.0.1';
        }

        if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && self::is_trusted_cloudflare_ip( $remote_addr ) ) {
            $cf_ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
            if ( filter_var( $cf_ip, FILTER_VALIDATE_IP ) ) {
                return $cf_ip;
            }
        }

        return $remote_addr;
    }

    /**
     * Checks whether an IP belongs to Cloudflare's published IP ranges (synced file + official fallback).
     */
    private static function is_trusted_cloudflare_ip( $ip ) {
        static $cf_ranges = null;
        if ( null === $cf_ranges ) {
            $cf_ranges = [];
            if ( function_exists( 'wp_upload_dir' ) ) {
                $upload_dir = wp_upload_dir();
                $paths = [
                    $upload_dir['basedir'] . '/nexura-security/cloudflare-ips.php',
                    $upload_dir['basedir'] . '/nexura-logs/cloudflare-ips.php',
                ];
                foreach ( $paths as $cf_file ) {
                    if ( file_exists( $cf_file ) ) {
                        $loaded = include $cf_file;
                        if ( is_array( $loaded ) && ! empty( $loaded ) ) {
                            $cf_ranges = $loaded;
                            break;
                        }
                    }
                }
            }
            if ( empty( $cf_ranges ) ) {
                // Official Cloudflare IPv4 + IPv6 fallback ranges
                $cf_ranges = [
                    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
                    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
                    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
                    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
                    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
                    '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
                ];
            }
        }

        foreach ( $cf_ranges as $cidr ) {
            if ( self::ip_in_cidr( $ip, $cidr ) ) {
                return true;
            }
        }
        return false;
    }

    /**
     * CIDR match supporting both IPv4 and IPv6.
     */
    private static function ip_in_cidr( $ip, $cidr ) {
        if ( strpos( $cidr, '/' ) === false ) {
            return $ip === $cidr;
        }
        list( $subnet, $mask ) = explode( '/', $cidr, 2 );
        $ip_bin     = @inet_pton( $ip );
        $subnet_bin = @inet_pton( $subnet );
        if ( false === $ip_bin || false === $subnet_bin || strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
            return false;
        }
        $mask = (int) $mask;
        $full_bytes = (int) floor( $mask / 8 );
        $rem_bits   = $mask % 8;

        if ( $full_bytes > 0 && substr( $ip_bin, 0, $full_bytes ) !== substr( $subnet_bin, 0, $full_bytes ) ) {
            return false;
        }
        if ( $rem_bits > 0 ) {
            $byte_mask = ( 0xFF << ( 8 - $rem_bits ) ) & 0xFF;
            if ( ( ord( $ip_bin[ $full_bytes ] ) & $byte_mask ) !== ( ord( $subnet_bin[ $full_bytes ] ) & $byte_mask ) ) {
                return false;
            }
        }
        return true;
    }
}
