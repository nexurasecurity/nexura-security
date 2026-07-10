<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * DB Scanner for detecting hidden administrators and malicious configurations.
 */
class DB_Scanner {

    /**
     * Scans for ghost administrators and suspicious admin accounts.
     */
    public function scan_hidden_admins() {
        global $wpdb;
        $findings = [];

        $meta_key = $wpdb->get_blog_prefix() . 'capabilities';
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        $admins = $wpdb->get_results( $wpdb->prepare(
            "SELECT user_id, meta_value FROM {$wpdb->usermeta} WHERE meta_key = %s AND meta_value LIKE %s",
            $meta_key,
            '%administrator%'
        ) );

        foreach ( $admins as $admin ) {
            $user = get_userdata( $admin->user_id );
            if ( ! $user ) {
                $findings[] = [
                    'pattern'     => 'Ghost Admin (ID: ' . $admin->user_id . ')',
                    'risk'        => 'High',
                    'description' => 'User has administrator capabilities in usermeta but does not exist in wp_users.',
                    'confidence'  => 100,
                    'line_number' => 0
                ];
            } else {
                if ( preg_match( '/(?:hacker|exploit|pwned|tempmail|10minutemail)/i', $user->user_email ) ) {
                    $findings[] = [
                        'pattern'     => 'Suspicious Admin Email (ID: ' . $admin->user_id . ')',
                        'risk'        => 'High',
                        'description' => 'Administrator has a highly suspicious email address.',
                        'confidence'  => 90,
                        'line_number' => 0
                    ];
                }
            }
        }

        return $findings;
    }

    /**
     * Scans options table for malicious redirects.
     */
    public function scan_malicious_options() {
        global $wpdb;
        $findings = [];

        $options_to_check = ['siteurl', 'home'];
        foreach ( $options_to_check as $opt ) {
            $val = get_option( $opt );
            // A basic regex for suspicious TLDs or known malicious patterns
            if ( preg_match( '/(?:spam|phishing|malware|xyz|click|redirect|ru|cn|bit|tk|ml|ga)/i', $val ) ) {
                // To avoid false positives on legitimate .ru/.cn domains, we keep risk at Medium unless it's very obvious
                $risk = preg_match( '/(?:spam|phishing|malware)/i', $val ) ? 'High' : 'Medium';
                
                $findings[] = [
                    'pattern'     => 'Malicious Redirect in "' . $opt . '"',
                    'risk'        => $risk,
                    'description' => 'The ' . $opt . ' option points to a potentially malicious domain.',
                    'confidence'  => 80,
                    'line_number' => 0
                ];
            }
        }

        return $findings;
    }

    /**
     * Runs all advanced DB scans.
     */
    public function run_advanced_db_scan() {
        $findings = [];
        $findings = array_merge( $findings, $this->scan_hidden_admins() );
        $findings = array_merge( $findings, $this->scan_malicious_options() );
        return $findings;
    }
}
