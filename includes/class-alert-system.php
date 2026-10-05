<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Alert System
 * 
 * Handles dispatching of security alerts via Email and Webhooks (Slack/Discord).
 */
class Alert_System {

    /**
     * Initializes the Alert System hooks.
     */
    public static function init() {
        add_action( 'NEXURA_send_alert_digest', [ __CLASS__, 'process_hourly_digest' ] );
    }

    /**
     * Send a security alert.
     *
     * @param string $title    The title of the alert.
     * @param string $message  The detailed message.
     * @param string $severity The severity level: 'info', 'medium', 'high', 'critical'.
     */
    public static function send_alert( $title, $message, $severity = 'high' ) {
        self::send_email( $title, $message, $severity );
        self::send_webhook( $title, $message, $severity );
    }

    /**
     * Send Email Alert with strict severity gating and hourly rate limiting.
     */
    private static function send_email( $title, $message, $severity ) {
        $enable_email = get_option( 'NEXURA_enable_email_alerts', '1' );
        if ( empty( $enable_email ) || '0' === (string) $enable_email ) {
            return;
        }

        // 1. Strict Severity Gating: Low & info events never send emails (dashboard/webhook only)
        $severity = strtolower( trim( $severity ) );
        if ( in_array( $severity, [ 'low', 'info' ], true ) ) {
            return;
        }

        if ( 'critical' === $severity && get_option( 'NEXURA_email_alerts_critical', '1' ) !== '1' ) {
            return;
        }
        if ( 'high' === $severity && get_option( 'NEXURA_email_alerts_high', '1' ) !== '1' ) {
            return;
        }
        if ( 'medium' === $severity && get_option( 'NEXURA_email_alerts_medium', '0' ) !== '1' ) {
            return;
        }

        // 2. Hourly Email Quota Protection (Anti-Email-Storm Budget)
        $hourly_limit = (int) get_option( 'NEXURA_hourly_email_limit', 5 );
        $hourly_limit = max( 1, min( 20, $hourly_limit ) ); // Safe bounds: 1 to 20 emails/hour

        $budget = get_transient( 'NEXURA_hourly_email_budget' );
        if ( ! is_array( $budget ) || ! isset( $budget['count'] ) ) {
            $budget = [
                'count'   => 0,
                'started' => time(),
            ];
        }

        if ( $budget['count'] >= $hourly_limit ) {
            // Hourly quota reached: buffer alert into digest queue to protect server from being blocked
            self::buffer_alert( $title, $message, $severity );
            return;
        }

        $to = self::get_recipients();
        if ( empty( $to ) ) {
            return;
        }

        $site_name = get_bloginfo( 'name' );
        $subject = sprintf( '[%s Security Alert] %s', $site_name, $title );
        
        $body = "Nexura Security Alert on {$site_name}\n\n";
        $body .= "Severity: " . strtoupper( $severity ) . "\n";
        $body .= "Title: {$title}\n\n";
        $body .= "{$message}\n\n";
        $body .= "Time: " . current_time( 'mysql' ) . "\n";
        $body .= "Site: " . site_url() . "\n";

        // Increment budget immediately so rapid consecutive calls and mail failures cannot bypass the limit
        $budget['count']++;
        $hour_secs = defined( 'HOUR_IN_SECONDS' ) ? HOUR_IN_SECONDS : 3600;
        $elapsed   = time() - $budget['started'];
        $remaining = max( 60, $hour_secs - $elapsed );
        set_transient( 'NEXURA_hourly_email_budget', $budget, $remaining );

        try {
            wp_mail( $to, $subject, $body );
        } catch ( \Throwable $e ) {
            // Silently catch mailer exceptions to prevent halting the parent process
        }
    }

    /**
     * Buffers an alert when the hourly email quota is exceeded.
     */
    private static function buffer_alert( $title, $message, $severity ) {
        $buffered = get_transient( 'NEXURA_buffered_alerts' );
        if ( ! is_array( $buffered ) ) {
            $buffered = [];
        }

        // Limit buffer to 50 alerts to prevent transient bloat
        if ( count( $buffered ) < 50 ) {
            $buffered[] = [
                'title'     => sanitize_text_field( $title ),
                'message'   => sanitize_text_field( $message ),
                'severity'  => sanitize_key( $severity ),
                'timestamp' => current_time( 'mysql' ),
            ];
            $hour_secs = defined( 'HOUR_IN_SECONDS' ) ? HOUR_IN_SECONDS : 3600;
            set_transient( 'NEXURA_buffered_alerts', $buffered, 2 * $hour_secs );
        }

        // Ensure digest dispatch event is scheduled for the next hour
        if ( ! wp_next_scheduled( 'NEXURA_send_alert_digest' ) ) {
            $hour_secs = defined( 'HOUR_IN_SECONDS' ) ? HOUR_IN_SECONDS : 3600;
            wp_schedule_single_event( time() + $hour_secs, 'NEXURA_send_alert_digest' );
        }
    }

    /**
     * Sends a consolidated hourly digest email for alerts suppressed by the rate limiter.
     */
    public static function process_hourly_digest() {
        $buffered = get_transient( 'NEXURA_buffered_alerts' );
        delete_transient( 'NEXURA_buffered_alerts' );

        if ( empty( $buffered ) || ! is_array( $buffered ) ) {
            return;
        }

        $count = count( $buffered );
        $site_name = get_bloginfo( 'name' );
        $subject = sprintf( '[%s Security Notice] Alert Digest: %d events suppressed (Quota Protected)', $site_name, $count );
        
        $body = "Nexura Security Notice on {$site_name}\n\n";
        $body .= "Anti-Email-Storm Notice:\n";
        $body .= "During high-traffic security activity, {$count} alerts were suppressed and bundled into this digest to protect your hosting server email quota from being blocked.\n\n";
        $body .= "=== Recent Security Events Summary ===\n\n";
        
        foreach ( array_slice( $buffered, 0, 15 ) as $alert ) {
            $body .= sprintf( "[%s] [%s] %s\n%s\n\n", $alert['timestamp'], strtoupper( $alert['severity'] ), $alert['title'], $alert['message'] );
        }
        
        if ( $count > 15 ) {
            $body .= "... and " . ( $count - 15 ) . " more events. Please log in to your WordPress dashboard to view full audit logs.\n\n";
        }
        
        $body .= "Dashboard: " . admin_url( 'admin.php?page=nexura' ) . "\n";
        $body .= "Time: " . current_time( 'mysql' ) . "\n";

        $to = self::get_recipients();
        if ( ! empty( $to ) ) {
            try {
                wp_mail( $to, $subject, $body );
            } catch ( \Throwable $e ) {
                // Silently catch mailer exceptions
            }
        }
    }

    /**
     * Gets valid alert recipient email addresses.
     */
    public static function get_recipients() {
        $custom_emails = get_option( 'NEXURA_alert_email_address' );
        if ( ! empty( $custom_emails ) ) {
            $emails = array_map( 'trim', explode( ',', $custom_emails ) );
            $to = array_filter( $emails, 'is_email' );
            if ( ! empty( $to ) ) {
                return array_values( $to );
            }
        }
        $admin_email = get_option( 'admin_email' );
        return ! empty( $admin_email ) ? $admin_email : '';
    }

    /**
     * Send Webhook Alert (Slack/Discord format)
     */
    public static function send_webhook( $title, $message, $severity ) {
        $enable_webhook = get_option( 'NEXURA_enable_webhook_alerts' );
        $webhook_url    = get_option( 'NEXURA_webhook_url' );

        if ( empty( $enable_webhook ) || empty( $webhook_url ) ) {
            return;
        }

        $color = '#36a64f'; // info (green)
        if ( 'medium' === $severity ) {
            $color = '#ffcc00'; // yellow
        } elseif ( 'high' === $severity ) {
            $color = '#ff9900'; // orange
        } elseif ( 'critical' === $severity ) {
            $color = '#ff0000'; // red
        }

        $site_name = get_bloginfo( 'name' );

        $payload = [
            'username'   => 'Nexura Security',
            'icon_emoji' => ':shield:',
            'attachments' => [
                [
                    'fallback' => "[{$site_name}] {$title} - {$message}",
                    'color'    => $color,
                    'title'    => "[{$site_name}] {$title}",
                    'text'     => $message,
                    'fields'   => [
                        [
                            'title' => 'Severity',
                            'value' => strtoupper( $severity ),
                            'short' => true
                        ],
                        [
                            'title' => 'Time',
                            'value' => current_time( 'mysql' ),
                            'short' => true
                        ]
                    ],
                    'footer' => 'Nexura Security Alert System'
                ]
            ]
        ];

        // Ensure Discord compatibility by adding content field if not present
        if ( strpos( $webhook_url, 'discord.com' ) !== false || strpos( $webhook_url, 'discordapp.com' ) !== false ) {
            $payload['content'] = '';
        }

        wp_remote_post( $webhook_url, [
            'headers'     => [ 'Content-Type' => 'application/json' ],
            'body'        => wp_json_encode( $payload ),
            'timeout'     => 10,
            'blocking'    => false, // Don't block page load waiting for webhook response
            'data_format' => 'body',
        ]);
    }
}
