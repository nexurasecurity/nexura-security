<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Cron
 * 
 * Handles WP-Cron scheduling for automated background scans.
 */
class Cron {

    /**
     * Initializes the cron hooks.
     */
    public function init() {
        // Register custom cron schedules (intervals)
        add_filter( 'cron_schedules', [ $this, 'add_custom_schedules' ] );

        // FIM and GSB recurring events
        add_action( 'NEXURA_daily_fim_check', [ $this, 'run_scheduled_fim' ] );
        add_action( 'NEXURA_daily_gsb_check', [ $this, 'run_scheduled_gsb' ] );
        add_action( 'NEXURA_daily_malware_scan', [ $this, 'run_scheduled_malware_scan' ] );

        // The background processing event that processes batches of the queue
        add_action( 'NEXURA_process_queue', [ $this, 'process_queue_batch' ] );

        add_action( 'admin_init', [ $this, 'schedule_default_crons' ] );
    }

    public function schedule_default_crons() {
        // Ensure daily schedules are active.
        // Note: First run is delayed by 1 hour to prevent timeout on activation.
        if ( ! wp_next_scheduled( 'NEXURA_daily_fim_check' ) ) {
            wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'NEXURA_daily_fim_check' );
        }
        if ( ! wp_next_scheduled( 'NEXURA_daily_gsb_check' ) ) {
            wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'NEXURA_daily_gsb_check' );
        }
        if ( ! wp_next_scheduled( 'NEXURA_daily_malware_scan' ) ) {
            // Schedule malware scan daily, but delay the first run slightly so it doesn't run exactly with FIM
            wp_schedule_event( time() + HOUR_IN_SECONDS + 1800, 'daily', 'NEXURA_daily_malware_scan' );
        }
    }

    /**
     * Adds custom time intervals to WP-Cron.
     *
     * @param array $schedules
     * @return array
     */
    public function add_custom_schedules( $schedules ) {
        $schedules['two_hours'] = [
            'interval' => 2 * HOUR_IN_SECONDS,
            'display'  => __( 'Every Two Hours', 'nexura-security' )
        ];
        
        $schedules['monthly'] = [
            'interval' => 30 * DAY_IN_SECONDS,
            'display'  => __( 'Once a Month', 'nexura-security' )
        ];

        return $schedules;
    }



    /**
     * Callback to process a batch of the scan queue in the background.
     */
    public function process_queue_batch() {
        $scanner = new Scanner();
        $response = $scanner->process_scan_batch();

        if ( $response['status'] === 'processing' ) {
            // Re-schedule this event to run immediately so it processes the next chunk
            wp_schedule_single_event( time(), 'NEXURA_process_queue' );
        } else {
            if ( class_exists( '\Nexura_Security\Logger' ) ) {
                Logger::log( 'Automated scheduled scan completed. Processed ' . $response['processed'] . ' files, found ' . $response['issues'] . ' issues.' );
            }
            $this->send_scan_report_email( $response );
        }
    }

    /**
     * Sends an email report after the scan is complete (Free version only).
     */
    private function send_scan_report_email( $response ) {
        if ( class_exists( '\Nexura_Security\Report_Generator' ) ) {
            \Nexura_Security\Report_Generator::generate_and_send( $response );
        }
    }

    /**
     * Callback to initialize the automated daily malware scan.
     */
    public function run_scheduled_malware_scan() {
        // Let Pro version handle its own scheduled scans
        if ( function_exists( 'nexura_is_pro' ) && nexura_is_pro() ) {
            return;
        }

        $scanner = new Scanner();
        $scanner->init_scan();
        // Start the background processing
        wp_schedule_single_event( time(), 'NEXURA_process_queue' );
    }

    /**
     * Callback to run FIM check daily.
     */
    public function run_scheduled_fim() {
        $fim = new File_Integrity();
        $response = $fim->check_integrity();
        if ( isset($response['error']) ) {
            if ( class_exists( '\Nexura_Security\Logger' ) ) {
                Logger::log( 'Scheduled FIM Check error: ' . $response['error'] );
            }
        } else {
            $changes = count($response['added']) + count($response['modified']) + count($response['deleted']);
            if ($changes > 0) {
                if ( class_exists( '\Nexura_Security\Logger' ) ) {
                    Logger::log( 'Scheduled FIM Check found ' . $changes . ' unauthorized file changes.' );
                }
            }
        }
    }

    /**
     * Callback to run GSB check daily.
     */
    public function run_scheduled_gsb() {
        $gsb = new Google_Safe();
        $response = $gsb->check_site();
        if ( isset($response['error']) ) {
            if ( class_exists( '\Nexura_Security\Logger' ) ) {
                Logger::log( 'Scheduled GSB Check error: ' . $response['error'] );
            }
        } elseif ( !$response['safe'] ) {
            if ( class_exists( '\Nexura_Security\Logger' ) ) {
                Logger::log( 'CRITICAL: Google Safe Browsing flagged this site as unsafe!' );
            }
        }
    }
}
