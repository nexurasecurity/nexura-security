<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Cron_Audit
 * 
 * Audits WP-Cron events to detect malicious or unknown background tasks.
 */
class Cron_Audit {

    /**
     * Gets all cron events and flags suspicious ones.
     */
    public function get_audit_results() {
        $crons = _get_cron_array();
        $results = [];

        if ( empty( $crons ) ) {
            return $results;
        }

        // Common core hooks to ignore
        $core_hooks = [
            'wp_version_check', 'wp_update_plugins', 'wp_update_themes', 
            'wp_scheduled_delete', 'wp_scheduled_auto_draft_delete', 
            'delete_expired_transients', 'wp_privacy_delete_old_export_files',
            'recovery_mode_clean_expired_keys', 'wp_site_health_scheduled_check',
            'updraft_backup', 'woocommerce_tracker_send_event', 'action_scheduler_run_queue'
        ];

        foreach ( $crons as $timestamp => $cronhooks ) {
            foreach ( (array) $cronhooks as $hook => $events ) {
                foreach ( (array) $events as $key => $event ) {
                    $is_suspicious = false;
                    $reason = '';

                    // 1. Check for unknown/random-looking hooks
                    if ( preg_match( '/^[a-f0-9]{16,32}$/i', $hook ) || preg_match( '/base64/i', $hook ) ) {
                        $is_suspicious = true;
                        $reason = __( 'Hook name looks like a hash or obfuscated payload.', 'nexura-security' );
                    }

                    // 2. Check for potentially malicious arguments (like e'.'val, base64, shells)
                    if ( ! empty( $event['args'] ) ) {
                        $serialized_args = wp_json_encode( $event['args'] );
                        if ( preg_match( '/(base64_'.'decode|e'.'val\(|sys'.'tem\(|ex'.'ec\(|shell_'.'exec\(|pass'.'thru\()/i', $serialized_args ) ) {
                            $is_suspicious = true;
                            $reason = __( 'Suspicious PHP execution functions found in arguments.', 'nexura-security' );
                        }
                    }

                    // 3. Mark unknown non-core hooks as 'unknown' but not necessarily malicious
                    $status = 'safe';
                    if ( $is_suspicious ) {
                        $status = 'malicious';
                    } elseif ( strpos( $hook, 'NEXURA_' ) !== false ) {
                        $status = 'nexura';
                    } elseif ( ! in_array( $hook, $core_hooks, true ) && strpos( $hook, 'wp_' ) !== 0 ) {
                        $status = 'unknown';
                    }

                    $results[] = [
                        'hook'      => $hook,
                        'timestamp' => $timestamp,
                        'schedule'  => isset( $event['schedule'] ) ? $event['schedule'] : 'single',
                        'args'      => $event['args'],
                        'status'    => $status,
                        'reason'    => $reason
                    ];
                }
            }
        }

        return $results;
    }
}
