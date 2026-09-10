<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Audit_Logger
 * 
 * Tracks admin creations, privilege escalations, and suspicious logins.
 */
class Audit_Logger {

    public function init() {
        add_action( 'user_register', [ $this, 'log_new_user' ], 10, 1 );
        add_action( 'set_user_role', [ $this, 'log_role_change' ], 10, 3 );
        add_action( 'wp_login', [ $this, 'log_suspicious_login' ], 10, 2 );
    }

    /**
     * Logs when a new user is registered (flags if admin).
     */
    public function log_new_user( $user_id ) {
        $user = get_userdata( $user_id );
        if ( ! $user ) {
            return;
        }

        if ( in_array( 'administrator', (array) $user->roles, true ) ) {
            $this->log_event(
                $user_id,
                $user->user_login,
                'new_admin',
                'critical',
                __( 'A new administrator account was created.', 'nexura-security' )
            );
            $this->send_alert_email( $user->user_login, 'New Administrator Created' );
        }
    }

    /**
     * Logs when a user's role is changed.
     */
    public function log_role_change( $user_id, $role, $old_roles ) {
        if ( $role === 'administrator' && ! in_array( 'administrator', (array) $old_roles, true ) ) {
            $user = get_userdata( $user_id );
            if ( $user ) {
                $this->log_event(
                    $user_id,
                    $user->user_login,
                    'privilege_escalation',
                    'critical',
                    __( 'User privilege was escalated to administrator.', 'nexura-security' )
                );
                $this->send_alert_email( $user->user_login, 'Privilege Escalation Detected' );
            }
        }
    }

    /**
     * Logs logins and detects if it is suspicious (e.g. new IP).
     */
    public function log_suspicious_login( $user_login, $user ) {
        $ip = $this->get_client_ip();
        $known_ips = get_user_meta( $user->ID, 'NEXURA_known_ips', true );
        
        if ( ! is_array( $known_ips ) ) {
            $known_ips = [];
        }

        if ( ! in_array( $ip, $known_ips, true ) ) {
            // New IP detected!
            $severity = in_array( 'administrator', (array) $user->roles, true ) ? 'high' : 'medium';
            $message = sprintf(
                /* translators: %s: IP Address */
                __( 'Successful login from a new IP Address: %s.', 'nexura-security' ),
                $ip
            );

            $this->log_event( $user->ID, $user->user_login, 'suspicious_login', $severity, $message );
            $this->send_alert_email( $user->user_login, 'Suspicious Login Detected', $severity );

            // Add IP to known IPs to prevent spamming
            $known_ips[] = $ip;
            // Keep only last 10 IPs to prevent meta bloat
            if ( count( $known_ips ) > 10 ) {
                array_shift( $known_ips );
            }
            update_user_meta( $user->ID, 'NEXURA_known_ips', $known_ips );
        }
    }

    /**
     * Inserts the event into the database.
     */
    private function log_event( $user_id, $username, $event_type, $severity, $message ) {
        global $wpdb;
        $table = $wpdb->prefix . 'NEXURA_audit_logs';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $wpdb->insert(
            $table,
            [
                'user_id'    => $user_id,
                'username'   => $username,
                'event_type' => $event_type,
                'severity'   => $severity,
                'message'    => $message,
                'ip_address' => $this->get_client_ip(),
                'timestamp'  => current_time( 'mysql' )
            ],
            [
                '%d',
                '%s',
                '%s',
                '%s',
                '%s',
                '%s',
                '%s'
            ]
        );
    }

    /**
     * Sends an email alert for critical events.
     */
    private function send_alert_email( $username, $subject_prefix, $severity = 'critical' ) {
        // Check global alert toggle
        if ( get_option( 'NEXURA_enable_email_alerts' ) !== '1' ) {
            return;
        }

        // Check specific severity toggles
        if ( $severity === 'critical' && get_option( 'NEXURA_email_alerts_critical', '1' ) !== '1' ) {
            return;
        }
        if ( $severity === 'high' && get_option( 'NEXURA_email_alerts_high', '1' ) !== '1' ) {
            return;
        }
        if ( $severity === 'medium' && get_option( 'NEXURA_email_alerts_medium', '0' ) !== '1' ) {
            return;
        }

        $admin_email = get_option( 'NEXURA_alert_email_address' );
        if ( empty( $admin_email ) ) {
            $admin_email = get_option( 'admin_email' );
        }

        $site_name = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );
        $ip = $this->get_client_ip();
        
        $subject = sprintf( '[%s] Security Alert: %s', $site_name, $subject_prefix );
        $message = sprintf(
            /* translators: 1: Event type, 2: Username, 3: IP Address, 4: Severity, 5: Timestamp */
            __( "A security event occurred on your site:\n\nEvent: %1\$s\nUser: %2\$s\nIP Address: %3\$s\nSeverity: %4\$s\nTime: %5\$s\n\nIf you did not authorize this action, please investigate immediately.", 'nexura-security' ),
            $subject_prefix,
            $username,
            $ip,
            strtoupper( $severity ),
            current_time( 'mysql' )
        );

        wp_mail( $admin_email, $subject, $message );
    }

    /**
     * Gets the real IP address of the user.
     */
    private function get_client_ip() {
        // REMOTE_ADDR is the only header that cannot be spoofed — always use it as the base.
        $ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '127.0.0.1';
        return $ip;
    }
}
