<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Security_Score
 * 
 * Calculates a 0-100 risk score based on active security features and vulnerabilities.
 */
class Security_Score {

    /**
     * Calculate the overall security score.
     * 
     * @return int The calculated score (0-100).
     */
    public static function get_score() {
        $score = 0;
        $max_score = 100;

        // 1. WAF & Bot Protection (30 points)
        $waf = get_option( 'NEXURA_enable_waf', 1 );
        if ( $waf && $waf !== 'disabled' && $waf !== '0' ) {
            $score += 15;
        }
        if ( get_option( 'NEXURA_enable_bot_protection', 1 ) ) {
            $score += 15;
        }

        // 2. Vulnerability Checks (30 points)
        // Deduct points if updates are available.
        $vuln_points = 30;
        
        $php_version = phpversion();
        if ( version_compare( $php_version, '7.4.0', '<' ) ) {
            $vuln_points -= 10;
        }

        $core_updates = get_site_transient( 'update_core' );
        global $wp_version;
        if ( isset( $core_updates->updates ) && is_array( $core_updates->updates ) ) {
            foreach ( $core_updates->updates as $update ) {
                if ( $update->response === 'upgrade' && version_compare( $wp_version, $update->version, '<' ) ) {
                    $vuln_points -= 10;
                    break;
                }
            }
        }

        $plugin_updates = get_site_transient( 'update_plugins' );
        if ( isset( $plugin_updates->response ) && is_array( $plugin_updates->response ) && ! empty( $plugin_updates->response ) ) {
            $vuln_points -= 10;
        }

        $score += max( 0, $vuln_points );

        // 3. Security Hardening & Headers (20 points)
        if ( get_option( 'NEXURA_add_security_headers', 0 ) ) {
            $score += 10;
        }
        if ( get_option( 'NEXURA_disable_file_editor', 0 ) ) {
            $score += 10;
        }

        // 4. Two-Factor Authentication & Login Security (20 points)
        if ( get_option( 'NEXURA_enable_2fa', 0 ) ) {
            $score += 15;
        }
        if ( get_option( 'NEXURA_enable_pwned_check', 0 ) ) {
            $score += 5;
        }

        // Ensure score stays within 0-100
        return max( 0, min( $score, $max_score ) );
    }

    /**
     * Determine the risk level based on the score.
     * 
     * @param int $score The security score.
     * @return array Contains 'label' and 'color'.
     */
    public static function get_risk_level( $score ) {
        if ( $score >= 90 ) {
            return [ 'label' => 'Excellent', 'color' => '#10b981' ]; // Green
        } elseif ( $score >= 70 ) {
            return [ 'label' => 'Good', 'color' => '#3b82f6' ]; // Blue
        } elseif ( $score >= 50 ) {
            return [ 'label' => 'Fair', 'color' => '#f59e0b' ]; // Yellow
        } else {
            return [ 'label' => 'Critical Risk', 'color' => '#ef4444' ]; // Red
        }
    }
}
