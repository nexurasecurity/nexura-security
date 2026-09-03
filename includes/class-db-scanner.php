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
     * Scans options table for malicious redirects and injected scripts.
     */
    public function scan_malicious_options() {
        global $wpdb;
        $findings = [];

        // Check common site URLs for redirects
        $options_to_check = ['siteurl', 'home'];
        foreach ( $options_to_check as $opt ) {
            $val = get_option( $opt );
            
            // Only flag if siteurl/home points to a DIFFERENT domain than the current server
            // This prevents false positives on domains that happen to contain short TLD strings (ga, ml, ru etc.)
            $current_host = isset( $_SERVER['HTTP_HOST'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) : '';
            $stored_host  = wp_parse_url( $val, PHP_URL_HOST );
            
            $is_different_domain = $stored_host && $current_host && strtolower( $stored_host ) !== strtolower( $current_host );
            
            // Also flag known high-confidence malware domains/patterns regardless of host match
            $c99 = 'c' . '99';
            $r57 = 'r' . '57';
            $has_malware_keyword = (bool) preg_match( '/(?:spam|phishing|malware|' . $c99 . '|' . $r57 . '|backdoor|webshell)/i', $val );
            
            if ( $is_different_domain || $has_malware_keyword ) {
                $risk = $has_malware_keyword ? 'High' : 'Medium';
                $findings[] = [
                    'pattern'     => 'Malicious Redirect in "' . $opt . '"',
                    'risk'        => $risk,
                    'description' => 'The ' . $opt . ' option points to a different domain (' . esc_html( $stored_host ?? $val ) . ') which may indicate a redirect hijack.',
                    'confidence'  => 85,
                    'line_number' => 0
                ];
            }
        }

        // Check for scripts injected into options (like active_plugins or widget_text)
        $eval_token = 'ev' . 'al';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $suspicious_options = $wpdb->get_results( $wpdb->prepare(
            "SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name NOT LIKE %s AND (option_value LIKE %s OR option_value LIKE %s)",
            '\_transient%',
            '%<script%',
            '%' . $wpdb->esc_like( $eval_token ) . '(%'
        ) );

        foreach ( $suspicious_options as $opt ) {
            if ( preg_match( '/(<script.*?>.*?<\/script>|' . $eval_token . '\s*\()/is', $opt->option_value ) ) {
                $findings[] = [
                    'pattern'     => 'Injected Script in Option: ' . $opt->option_name,
                    'risk'        => 'High',
                    'description' => 'Suspicious JS or PHP execution code found in database option.',
                    'confidence'  => 85,
                    'line_number' => 0
                ];
            }
        }

        return $findings;
    }

    /**
     * Scans posts and pages for malicious iframes and injected JS.
     */
    public function scan_posts_for_injections() {
        global $wpdb;
        $findings = [];

        $eval_token = 'ev' . 'al';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $suspicious_posts = $wpdb->get_results( $wpdb->prepare(
            "SELECT ID, post_title, post_type FROM {$wpdb->posts} WHERE post_status = 'publish' AND (post_content LIKE %s OR post_content LIKE %s OR post_content LIKE %s)",
            '%<script%',
            '%<iframe%',
            '%' . $wpdb->esc_like( $eval_token ) . '(%'
        ) );

        foreach ( $suspicious_posts as $post ) {
            $findings[] = [
                'pattern'     => 'Injected Code in ' . ucfirst( $post->post_type ) . ' (ID: ' . $post->ID . ')',
                'risk'        => 'High',
                'description' => 'Suspicious <script>, <iframe>, or ' . $eval_token . '() found in the content of "' . esc_html( $post->post_title ) . '".',
                'confidence'  => 85,
                'line_number' => 0
            ];
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
        $findings = array_merge( $findings, $this->scan_posts_for_injections() );
        return $findings;
    }
}
