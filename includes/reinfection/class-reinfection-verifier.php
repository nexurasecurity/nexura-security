<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Reinfection_Verifier
 *
 * After remediation, verifies that the malware has NOT returned.
 * This is the Sprint 6 "Verification" step.
 *
 * Methodology:
 * 1. Hash the target file at time of remediation.
 * 2. On a subsequent call, re-check if the file has reappeared.
 * 3. Compare hashes to confirm it is the same malware, not a legit file.
 */
class Reinfection_Verifier {

    const SNAPSHOTS_OPTION = 'NEXURA_reinfection_snapshots';

    /**
     * Record a snapshot of a remediated target.
     * Call this AFTER quarantining / cleaning the file.
     *
     * @param string $file_path    Absolute path of the remediated file.
     * @param string $finding_type Type of persistence mechanism removed.
     * @return void
     */
    public function record_snapshot( $file_path, $finding_type = 'file' ) {
        $snapshots = get_option( self::SNAPSHOTS_OPTION, [] );

        $snapshots[ md5( $file_path ) ] = [
            'path'         => $file_path,
            'type'         => $finding_type,
            'remediated_at'=> current_time( 'mysql' ),
            'original_hash'=> file_exists( $file_path ) ? md5_file( $file_path ) : null,
            'verified'     => false,
        ];

        update_option( self::SNAPSHOTS_OPTION, $snapshots, false );
    }

    /**
     * Run a verification pass over all recorded snapshots.
     * Checks if any remediated files have returned.
     *
     * @return array Array of reinfection alerts.
     */
    public function verify_all() {
        $snapshots = get_option( self::SNAPSHOTS_OPTION, [] );
        $alerts    = [];

        if ( empty( $snapshots ) ) {
            return $alerts;
        }

        foreach ( $snapshots as $key => $snap ) {
            $path = $snap['path'];

            // If the file has come back...
            if ( file_exists( $path ) ) {
                $current_hash = md5_file( $path );

                $alerts[] = [
                    'type'          => 'reinfection_detected',
                    'path'          => $path,
                    'remediated_at' => $snap['remediated_at'],
                    'verified_at'   => current_time( 'mysql' ),
                    'evidence'      => "File '{$path}' was quarantined but has returned. The persistence mechanism may not have been fully removed.",
                    'risk'          => 95,
                    'hash_changed'  => ( $current_hash !== $snap['original_hash'] ),
                ];

                // Write to audit log if the logger is available
                $this->log_reinfection( $path, $snap );

            } else {
                // File is still gone — mark as verified clean
                $snapshots[ $key ]['verified'] = true;
            }
        }

        update_option( self::SNAPSHOTS_OPTION, $snapshots, false );

        return $alerts;
    }

    /**
     * Verify a specific file only.
     *
     * @param string $file_path Absolute path to check.
     * @return array
     */
    public function verify_file( $file_path ) {
        if ( ! file_exists( $file_path ) ) {
            return [ 'reinfected' => false, 'message' => 'File has not returned. Clean.' ];
        }

        return [
            'reinfected' => true,
            'path'       => $file_path,
            'message'    => "File '{$file_path}' has returned — persistence mechanism still active.",
            'risk'       => 95,
        ];
    }

    /**
     * Log a reinfection event to the NEXURA audit log.
     *
     * @param string $path The reinfected file path.
     * @param array  $snap The snapshot data.
     */
    private function log_reinfection( $path, $snap ) {
        global $wpdb;

        $table = $wpdb->prefix . 'NEXURA_audit_logs';
        $actual = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

        if ( ! $actual || strcasecmp( $actual, $table ) !== 0 ) {
            return;
        }

        $wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
            $table,
            [
                'user_id'    => 0,
                'username'   => 'Nexura Reinfection Guard',
                'event_type' => 'reinfection_detected',
                'severity'   => 'Critical',
                'message'    => "Reinfection detected: {$path} (originally remediated at {$snap['remediated_at']})",
                'ip_address' => '0.0.0.0',
                'timestamp'  => current_time( 'mysql' ),
            ],
            [ '%d', '%s', '%s', '%s', '%s', '%s', '%s' ]
        );
    }
}
