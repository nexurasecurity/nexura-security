<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class DB_Persistence_Analyzer
 *
 * Analyzes Database for persistent payloads:
 * - wp_options (autoloaded) injected code
 * - MySQL TRIGGERS (sophisticated persistence vector)
 */
class DB_Persistence_Analyzer {

    /**
     * Run all DB checks.
     *
     * @return array Array of findings.
     */
    public function analyze_db() {
        $findings = [];
        $findings = array_merge( $findings, $this->scan_wp_options() );
        $findings = array_merge( $findings, $this->scan_mysql_triggers() );
        return $findings;
    }

    /**
     * Scan wp_options for injected payload strings.
     *
     * @return array
     */
    private function scan_wp_options() {
        $findings = [];
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $options = $wpdb->get_results( "SELECT option_name, option_value FROM {$wpdb->options} WHERE autoload = 'yes'" );

        $suspicious_keywords = [ 'base64_decode', 'eval(', 'system(', 'shell_exec(', 'passthru(', 'assert(' ];

        foreach ( $options as $opt ) {
            if ( strpos( $opt->option_name, 'NEXURA_' ) === 0 ) {
                continue;
            }
            foreach ( $suspicious_keywords as $keyword ) {
                if ( stripos( $opt->option_value, $keyword ) !== false ) {
                    $findings[] = [
                        'type'     => 'db_payload',
                        'option'   => $opt->option_name,
                        'evidence' => "Suspicious payload in wp_options -> {$opt->option_name} (contains: {$keyword})",
                        'risk'     => 90,
                    ];
                    break;
                }
            }
        }

        return $findings;
    }

    /**
     * Detect MySQL TRIGGERS — a sophisticated persistence mechanism.
     * Attackers use triggers to re-inject malware on DB events (INSERT/UPDATE).
     *
     * @return array
     */
    private function scan_mysql_triggers() {
        $findings = [];
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $triggers = $wpdb->get_results( 'SHOW TRIGGERS' );

        if ( empty( $triggers ) ) {
            return $findings;
        }

        // WordPress core does NOT create any triggers.
        // Any trigger found is highly suspicious.
        foreach ( $triggers as $trigger ) {
            $trigger_name  = isset( $trigger->Trigger ) ? $trigger->Trigger : 'unknown';
            $trigger_table = isset( $trigger->Table ) ? $trigger->Table : 'unknown';
            $trigger_stmt  = isset( $trigger->Statement ) ? $trigger->Statement : '';

            $findings[] = [
                'type'     => 'db_trigger',
                'option'   => $trigger_name,
                'evidence' => "MySQL TRIGGER '{$trigger_name}' found on table '{$trigger_table}'. WordPress does not use DB triggers — this is a critical persistence vector.",
                'risk'     => 95,
                'detail'   => wp_strip_all_tags( $trigger_stmt ),
            ];
        }

        return $findings;
    }
}

