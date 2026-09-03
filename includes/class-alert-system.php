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
     * Send Email Alert
     */
    private static function send_email( $title, $message, $severity ) {
        $enable_email = get_option( 'NEXURA_enable_email_alerts', '1' );
        if ( empty( $enable_email ) || '0' === (string) $enable_email ) {
            return;
        }

        $custom_emails = get_option( 'NEXURA_alert_email_address' );
        if ( ! empty( $custom_emails ) ) {
            // Support comma-separated emails
            $emails = array_map( 'trim', explode( ',', $custom_emails ) );
            $to = array_filter( $emails, 'is_email' );
        } else {
            // Default to admin email
            $to = get_option( 'admin_email' );
        }

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

        wp_mail( $to, $subject, $body );
    }

    /**
     * Send Webhook Alert (Slack/Discord format)
     */
    private static function send_webhook( $title, $message, $severity ) {
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
