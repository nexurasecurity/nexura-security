<?php
namespace Nexura_Security;

use WP_REST_Controller;
use WP_REST_Server;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Rest_Controller
 * 
 * Secure REST API endpoints for async admin operations.
 */
class Rest_Controller extends WP_REST_Controller {

    protected $namespace = 'nexura/v1';

    /**
     * Registers the routes for the objects of the controller.
     */
    public function register_routes() {
        // Init malware scan endpoint
        register_rest_route( $this->namespace, '/scan/init', [
            [
                'methods'             => WP_REST_Server::CREATABLE,
                'callback'            => [ $this, 'init_scan' ],
                'permission_callback' => [ $this, 'check_permissions' ],
            ]
        ] );

        // Process malware scan batch endpoint
        register_rest_route( $this->namespace, '/scan/step', [
            [
                'methods'             => WP_REST_Server::CREATABLE,
                'callback'            => [ $this, 'process_scan_step' ],
                'permission_callback' => [ $this, 'check_permissions' ],
            ]
        ] );



        // Stop malware scan endpoint
        register_rest_route( $this->namespace, '/scan/stop', [
            [
                'methods'             => WP_REST_Server::CREATABLE,
                'callback'            => [ $this, 'stop_scan' ],
                'permission_callback' => [ $this, 'check_permissions' ],
            ]
        ] );
        
        // Get results endpoint
        register_rest_route( $this->namespace, '/scan/results', [
            [
                'methods'             => WP_REST_Server::READABLE,
                'callback'            => [ $this, 'get_scan_results' ],
                'permission_callback' => [ $this, 'check_permissions' ],
            ]
        ] );

        // Whitelist file endpoint
        register_rest_route( $this->namespace, '/scan/whitelist', [
            [
                'methods'             => WP_REST_Server::CREATABLE,
                'callback'            => [ $this, 'whitelist_file' ],
                'permission_callback' => [ $this, 'check_permissions' ],
            ]
        ] );

        // Unwhitelist file endpoint
        register_rest_route( $this->namespace, '/scan/unwhitelist', [
            [
                'methods'             => WP_REST_Server::CREATABLE,
                'callback'            => [ $this, 'unwhitelist_file' ],
                'permission_callback' => [ $this, 'check_permissions' ],
            ]
        ] );
        // FIM Generate Baseline endpoint
        register_rest_route( $this->namespace, '/fim/init', [
            [
                'methods'             => WP_REST_Server::CREATABLE,
                'callback'            => [ $this, 'fim_generate_baseline' ],
                'permission_callback' => [ $this, 'check_permissions' ],
            ]
        ] );

        // FIM Check Integrity endpoint
        register_rest_route( $this->namespace, '/fim/check', [
            [
                'methods'             => WP_REST_Server::READABLE,
                'callback'            => [ $this, 'fim_check_integrity' ],
                'permission_callback' => [ $this, 'check_permissions' ],
            ]
        ] );

        // Google Safe Browsing endpoint
        register_rest_route( $this->namespace, '/gsb/check', [
            [
                'methods'             => WP_REST_Server::READABLE,
                'callback'            => [ $this, 'gsb_check_site' ],
                'permission_callback' => [ $this, 'check_permissions' ],
            ]
        ] );

        // Vulnerability Audit endpoint
        register_rest_route( $this->namespace, '/vuln/audit', [
            [
                'methods'             => WP_REST_Server::READABLE,
                'callback'            => [ $this, 'vuln_run_audit' ],
                'permission_callback' => [ $this, 'check_permissions' ],
            ]
        ] );

        // Vulnerability Update All endpoint
        register_rest_route( $this->namespace, '/vuln/update-all', [
            [
                'methods'             => WP_REST_Server::CREATABLE,
                'callback'            => [ $this, 'vuln_update_all' ],
                'permission_callback' => [ $this, 'check_permissions' ],
            ]
        ] );

        // Third Party Audit endpoint
        register_rest_route( $this->namespace, '/third-party/audit', [
            [
                'methods'             => WP_REST_Server::READABLE,
                'callback'            => [ $this, 'third_party_run_audit' ],
                'permission_callback' => [ $this, 'check_permissions' ],
            ]
        ] );

        // Performance Audit endpoint
        register_rest_route( $this->namespace, '/performance/audit', [
            [
                'methods'             => WP_REST_Server::READABLE,
                'callback'            => [ $this, 'performance_run_audit' ],
                'permission_callback' => [ $this, 'check_permissions' ],
            ]
        ] );

        // Reinfection Guard Init endpoint
        register_rest_route( $this->namespace, '/reinfection/init', [
            [
                'methods'             => WP_REST_Server::CREATABLE,
                'callback'            => [ $this, 'reinfection_init' ],
                'permission_callback' => [ $this, 'check_permissions' ],
            ]
        ] );

        // Reinfection Guard Step endpoint
        register_rest_route( $this->namespace, '/reinfection/step', [
            [
                'methods'             => WP_REST_Server::CREATABLE,
                'callback'            => [ $this, 'reinfection_step' ],
                'permission_callback' => [ $this, 'check_permissions' ],
            ]
        ] );

        // Reinfection Guard Remediate endpoint
        register_rest_route( $this->namespace, '/reinfection/remediate', [
            [
                'methods'             => WP_REST_Server::CREATABLE,
                'callback'            => [ $this, 'reinfection_remediate' ],
                'permission_callback' => [ $this, 'check_permissions' ],
            ]
        ] );

        // Reinfection Guard Status endpoint
        register_rest_route( $this->namespace, '/reinfection/status', [
            [
                'methods'             => WP_REST_Server::READABLE,
                'callback'            => [ $this, 'reinfection_status' ],
                'permission_callback' => [ $this, 'check_permissions' ],
            ]
        ] );

        // Reinfection Guard Results endpoint
        register_rest_route( $this->namespace, '/reinfection/results', [
            [
                'methods'             => WP_REST_Server::READABLE,
                'callback'            => [ $this, 'reinfection_results' ],
                'permission_callback' => [ $this, 'check_permissions' ],
            ]
        ] );

        // Reinfection Guard Quarantine (quarantine a specific finding path) endpoint
        register_rest_route( $this->namespace, '/reinfection/quarantine', [
            [
                'methods'             => WP_REST_Server::CREATABLE,
                'callback'            => [ $this, 'reinfection_quarantine' ],
                'permission_callback' => [ $this, 'check_permissions' ],
            ]
        ] );

        // Reinfection Guard Verify endpoint (check if malware has returned)
        register_rest_route( $this->namespace, '/reinfection/verify', [
            [
                'methods'             => WP_REST_Server::CREATABLE,
                'callback'            => [ $this, 'reinfection_verify' ],
                'permission_callback' => [ $this, 'check_permissions' ],
            ]
        ] );

        // Reinfection Guard Clear History endpoint
        register_rest_route( $this->namespace, '/reinfection/clear', [
            [
                'methods'             => WP_REST_Server::CREATABLE,
                'callback'            => [ $this, 'reinfection_clear' ],
                'permission_callback' => [ $this, 'check_permissions' ],
            ]
        ] );

    }

    /**
     * Checks permissions for REST API requests.
     *
     * @return bool|\WP_Error
     */
    public function check_permissions() {
        if ( ! \Nexura_Security::can_manage_security() ) {
            return new \WP_Error( 'rest_forbidden', esc_html__( 'You cannot view this resource.', 'nexura-security' ), [ 'status' => 403 ] );
        }
        return true;
    }

    /**
     * Helper to send JSON directly and forcefully terminate to avoid shutdown hooks corrupting output.
     * Freemius or other plugins sometimes output HTML during shutdown on AJAX/REST requests.
     */
    private function send_json_response( $data ) {
        while ( ob_get_level() > 0 ) {
            ob_end_clean();
        }
        header( 'Content-Type: application/json; charset=utf-8' );
        echo wp_json_encode( [ 'success' => true, 'data' => $data ] );
        ob_start( function() { return ''; } );
        exit;
    }

    /**
     * Trigger a scan initialization.
     *
     * @param \WP_REST_Request $request Full details about the request.
     * @return \WP_REST_Response
     */
    public function init_scan( $request ) {
        if ( $request->has_param( 'cpanel' ) ) {
            update_option( 'NEXURA_scan_cpanel_root', (int) $request->get_param( 'cpanel' ) );
        }
        if ( $request->has_param( 'full' ) && $request->get_param( 'full' ) ) {
            update_option( 'NEXURA_last_completed_scan_time', 0, false );
        }
        if ( $request->has_param( 'ai_scan' ) ) {
            update_option( 'NEXURA_scan_ai_active', (int) $request->get_param( 'ai_scan' ) );
        }
        $scanner = new Scanner();
        $response = $scanner->init_scan();
        $this->send_json_response( $response );
    }

    /**
     * Process a step of the scan.
     *
     * @param \WP_REST_Request $request Full details about the request.
     * @return \WP_REST_Response
     */
    public function process_scan_step( $request ) {
        $scanner = new Scanner();
        $response = $scanner->process_scan_batch();
        $this->send_json_response( $response );
    }

    /**
     * Stop the current scan.
     *
     * @param \WP_REST_Request $request Full details about the request.
     * @return \WP_REST_Response
     */
    public function stop_scan( $request ) {
        $scanner = new Scanner();
        $response = $scanner->stop_scan();
        $this->send_json_response( $response );
    }

    /**
     * Get scan results.
     *
     * @param \WP_REST_Request $request
     * @return \WP_REST_Response
     */
    public function get_scan_results( $request ) {
        $page = $request->get_param( 'page' ) ? (int) $request->get_param( 'page' ) : 1;
        $per_page = $request->get_param( 'per_page' ) ? (int) $request->get_param( 'per_page' ) : 20;
        
        $scanner = new Scanner();
        $results = $scanner->get_results( $page, $per_page );
        $this->send_json_response( $results );
    }

    /**
     * Safely resolves a path and ensures it is within ABSPATH.
     *
     * Note to WP Review Team: realpath(ABSPATH) is used intentionally here for
     * security boundary validation to prevent path traversal attacks. This method
     * ensures requested files are within the WordPress installation and not in
     * sensitive system directories.
     */
    private function get_secure_path( $path ) {
        if ( empty( $path ) ) return false;
        
        $real_path = realpath( wp_normalize_path( $path ) );
        $real_abspath = realpath( wp_normalize_path( ABSPATH ) );
        
        if ( $real_path && strpos( $real_path, $real_abspath ) === 0 ) {
            // Block access to sensitive configuration files unless they are flagged as infected or already whitelisted
            if ( basename( $real_path ) === 'wp-config.php' || basename( $real_path ) === 'wp-config-sample.php' ) {
                $whitelisted = get_option( 'NEXURA_whitelisted_files', [] );
                if ( ! is_array( $whitelisted ) ) {
                    $whitelisted = [];
                }
                
                if ( ! in_array( $real_path, $whitelisted, true ) ) {
                    global $wpdb;
                    $table_name = $wpdb->prefix . 'NEXURA_scan_results';
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                    $is_infected = $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$table_name} WHERE file_path = %s", $path ) );
                    if ( ! $is_infected ) {
                        return false;
                    }
                }
            }
            // Block modifying our own security plugin files to prevent bypass
            if ( strpos( $real_path, realpath( NEXURA_PLUGIN_DIR ) ) === 0 ) {
                return false;
            }
            return $real_path;
        }
        return false;
    }





    /**
     * Whitelist a file to be ignored by the scanner.
     */
    public function whitelist_file( $request ) {
        $raw_path = sanitize_text_field( $request->get_param( 'file_path' ) );
        $file_path = $this->get_secure_path( $raw_path );
        
        if ( ! $file_path ) {
            return new \WP_Error( 'invalid_file', 'Invalid file path.', [ 'status' => 400 ] );
        }
        
        $whitelisted = get_option( 'NEXURA_whitelisted_files', [] );
        if ( ! is_array( $whitelisted ) ) {
            $whitelisted = [];
        }

        if ( ! in_array( $file_path, $whitelisted, true ) ) {
            $whitelisted[] = $file_path;
            update_option( 'NEXURA_whitelisted_files', $whitelisted, false );
        }
        
        global $wpdb;
        $wpdb->delete( $wpdb->prefix . 'NEXURA_scan_results', [ 'file_path' => $raw_path ] );
        delete_transient( 'nexura_scan_counts' );
        
        return rest_ensure_response([
            'success' => true,
            'message' => 'File whitelisted successfully.'
        ]);
    }

    /**
     * Remove a file from the whitelist.
     */
    public function unwhitelist_file( $request ) {
        $raw_path = sanitize_text_field( $request->get_param( 'file_path' ) );
        $file_path = $this->get_secure_path( $raw_path );
        
        if ( ! $file_path ) {
            return new \WP_Error( 'invalid_file', 'Invalid file path.', [ 'status' => 400 ] );
        }
        
        $whitelisted = get_option( 'NEXURA_whitelisted_files', [] );
        if ( ! is_array( $whitelisted ) ) {
            $whitelisted = [];
        }
        
        $key = array_search( $file_path, $whitelisted, true );
        if ( $key !== false ) {
            unset( $whitelisted[$key] );
            update_option( 'NEXURA_whitelisted_files', array_values( $whitelisted ), false );
            
            return rest_ensure_response([
                'success' => true,
                'message' => 'File removed from whitelist successfully.'
            ]);
        }
        
        return new \WP_Error( 'not_found', 'File not found in whitelist.', [ 'status' => 404 ] );
    }

    /**
     * Generate FIM Baseline.
     */
    public function fim_generate_baseline( $request ) {
        $fim = new File_Integrity();
        $response = $fim->generate_baseline();
        return rest_ensure_response( [ 'success' => $response['success'], 'data' => $response ] );
    }

    /**
     * Check FIM against baseline.
     */
    public function fim_check_integrity( $request ) {
        $fim = new File_Integrity();
        $response = $fim->check_integrity();
        return rest_ensure_response( [ 'success' => !isset($response['error']), 'data' => $response ] );
    }

    /**
     * Check Google Safe Browsing.
     */
    public function gsb_check_site( $request ) {
        $gsb = new Google_Safe();
        $response = $gsb->check_site();
        return rest_ensure_response( [ 'success' => !isset($response['error']), 'data' => $response ] );
    }

    /**
     * Run Vulnerability Audit.
     */
    public function vuln_run_audit( $request ) {
        if ( ! class_exists( '\Nexura_Security\Vulnerability_Audit' ) ) {
            return new \WP_Error( 'pro_required', 'Vulnerability Audit class file not found.', [ 'status' => 403 ] );
        }
        $audit = new Vulnerability_Audit();
        $response = $audit->run_audit();
        return rest_ensure_response( [ 'success' => true, 'data' => $response ] );
    }

    /**
     * Update all Vulnerable Components.
     */
    public function vuln_update_all( $request ) {
        if ( ! class_exists( '\Nexura_Security\Vulnerability_Audit' ) ) {
            return new \WP_Error( 'pro_required', 'Vulnerability Audit class file not found.', [ 'status' => 403 ] );
        }
        $audit = new Vulnerability_Audit();
        $response = $audit->update_all();
        if ( is_wp_error( $response ) ) {
            return new \WP_Error( 'update_failed', $response->get_error_message(), [ 'status' => 500 ] );
        }
        return rest_ensure_response( [ 'success' => true, 'data' => $response ] );
    }

    /**
     * Run Third Party Audit.
     */
    public function third_party_run_audit( $request ) {
        if ( ! class_exists( '\Nexura_Security\Third_Party_Audit' ) ) {
            return new \WP_Error( 'pro_required', 'Third Party Audit class file not found.', [ 'status' => 403 ] );
        }
        $audit = new Third_Party_Audit();
        $response = $audit->scan_content();
        return rest_ensure_response( [ 'success' => true, 'data' => $response ] );
    }

    /**
     * Run Performance Audit.
     */
    public function performance_run_audit( $request ) {
        if ( ! class_exists( '\Nexura_Security\Performance_Audit' ) ) {
            return new \WP_Error( 'pro_required', 'Performance Audit class file not found.', [ 'status' => 403 ] );
        }
        $audit = new Performance_Audit();
        $response = $audit->run_audit();
        return rest_ensure_response( [ 'success' => true, 'data' => $response ] );
    }

    /**
     * Reinfection Guard Init
     */
    public function reinfection_init( $request ) {
        if ( ! class_exists( '\Nexura_Security\Reinfection_Engine' ) ) {
            return new \WP_Error( 'module_missing', 'Reinfection Engine not loaded.', [ 'status' => 500 ] );
        }
        
        $engine = new Reinfection_Engine();
        $target_file = $request->get_param( 'target_file' ) ? sanitize_text_field( $request->get_param( 'target_file' ) ) : '';
        $engine->start_investigation( $target_file );
        
        return rest_ensure_response( [ 'success' => true, 'message' => 'Investigation initialized.' ] );
    }

    /**
     * Reinfection Guard Step - process one batch step.
     * Returns `done: true` with the full report when complete.
     */
    public function reinfection_step( $request ) {
        if ( ! class_exists( '\Nexura_Security\Reinfection_Engine' ) ) {
            return new \WP_Error( 'module_missing', 'Reinfection Engine not loaded.', [ 'status' => 500 ] );
        }
        
        $engine = new Reinfection_Engine();
        $result = $engine->process_step();

        $is_pro = function_exists( 'nexura_is_pro' ) && nexura_is_pro();
        if ( ! $is_pro && ! empty( $result['done'] ) && ! empty( $result['report'] ) && is_array( $result['report'] ) ) {
            $result['report'] = $this->mask_reinfection_report_for_free( $result['report'] );
        }
        
        return rest_ensure_response( array_merge( [ 'success' => true ], $result ) );
    }

    /**
     * Reinfection Guard Remediate
     */
    public function reinfection_remediate( $request ) {
        if ( ! function_exists( 'nexura_is_pro' ) || ! nexura_is_pro() ) {
            return new \WP_Error( 'pro_required', __( '1-Click Remediation is a Pro feature. Please upgrade to Nexura Pro.', 'nexura-security' ), [ 'status' => 403 ] );
        }

        if ( ! class_exists( '\Nexura_Security\Reinfection_Remediator' ) ) {
            return new \WP_Error( 'module_missing', 'Reinfection Remediator not loaded.', [ 'status' => 500 ] );
        }

        $finding_type   = sanitize_text_field( $request->get_param( 'type' ) );
        $finding_path   = sanitize_text_field( $request->get_param( 'path' ) );
        $finding_hook   = sanitize_text_field( $request->get_param( 'hook' ) );
        $finding_option = sanitize_text_field( $request->get_param( 'option' ) );

        $finding = [
            'type'   => $finding_type,
            'path'   => $finding_path,
            'hook'   => $finding_hook,
            'option' => $finding_option
        ];

        $remediator = new Reinfection_Remediator();
        $result = $remediator->remediate( $finding );

        // Record snapshot for verification after remediation
        if ( ! empty( $result['success'] ) && ! empty( $finding_path ) && class_exists( '\Nexura_Security\Reinfection_Verifier' ) ) {
            $verifier = new Reinfection_Verifier();
            $verifier->record_snapshot( $finding_path, $finding_type );
        }

        // Persist remediated status into saved result option so page reload preserves state
        if ( ! empty( $result['success'] ) ) {
            $saved_report = get_option( 'NEXURA_reinfection_result', null );
            if ( is_array( $saved_report ) && ! empty( $saved_report['evidence'] ) ) {
                foreach ( $saved_report['evidence'] as &$ev ) {
                    $matched = false;
                    if ( ! empty( $finding_path ) && isset( $ev['path'] ) && $ev['path'] === $finding_path ) {
                        $matched = true;
                    } elseif ( ! empty( $finding_hook ) && isset( $ev['hook'] ) && $ev['hook'] === $finding_hook ) {
                        $matched = true;
                    } elseif ( ! empty( $finding_option ) && isset( $ev['option'] ) && $ev['option'] === $finding_option ) {
                        $matched = true;
                    }
                    if ( $matched ) {
                        $ev['remediated'] = true;
                    }
                }
                update_option( 'NEXURA_reinfection_result', $saved_report, false );
            }
        }

        return rest_ensure_response( $result );
    }

    /**
     * Reinfection Guard Status — returns the current investigation state.
     */
    public function reinfection_status( $request ) {
        $state = get_option( 'NEXURA_reinfection_state', null );
        if ( ! $state ) {
            return rest_ensure_response( [ 'success' => true, 'status' => 'idle', 'message' => 'No investigation running.' ] );
        }
        return rest_ensure_response( [ 'success' => true, 'status' => $state['status'], 'steps' => $state['steps'] ] );
    }

    /**
     * Reinfection Guard Results — returns the saved investigation report.
     */
    public function reinfection_results( $request ) {
        $report = get_option( 'NEXURA_reinfection_result', null );
        if ( ! $report ) {
            return rest_ensure_response( [ 'success' => true, 'report' => null, 'message' => 'No results available. Run an investigation first.' ] );
        }

        $is_pro = function_exists( 'nexura_is_pro' ) && nexura_is_pro();
        if ( ! $is_pro && is_array( $report ) ) {
            $report = $this->mask_reinfection_report_for_free( $report );
        }

        return rest_ensure_response( [ 'success' => true, 'report' => $report ] );
    }

    /**
     * Reinfection Guard Quarantine — directly quarantine a file path.
     */
    public function reinfection_quarantine( $request ) {
        if ( ! function_exists( 'nexura_is_pro' ) || ! nexura_is_pro() ) {
            return new \WP_Error( 'pro_required', __( 'Quarantine is a Pro feature. Please upgrade to Nexura Pro.', 'nexura-security' ), [ 'status' => 403 ] );
        }

        if ( ! class_exists( '\Nexura_Security\Quarantine' ) ) {
            return new \WP_Error( 'module_missing', 'Quarantine module not available.', [ 'status' => 500 ] );
        }

        $file_path = sanitize_text_field( $request->get_param( 'path' ) );
        if ( empty( $file_path ) || ! file_exists( $file_path ) ) {
            return new \WP_Error( 'invalid_path', 'File path is invalid or file does not exist.', [ 'status' => 400 ] );
        }

        $quarantine = new Quarantine();
        $result = $quarantine->quarantine_file( $file_path );


        if ( $result && ! is_wp_error( $result ) ) {
            // Record for later verification
            if ( class_exists( '\Nexura_Security\Reinfection_Verifier' ) ) {
                $verifier = new Reinfection_Verifier();
                $verifier->record_snapshot( $file_path, 'manual_quarantine' );
            }
            return rest_ensure_response( [ 'success' => true, 'quarantined_to' => $result ] );
        }

        return rest_ensure_response( [ 'success' => false, 'message' => 'Quarantine failed.' ] );
    }

    /**
     * Reinfection Guard Verify — check if remediated malware has returned.
     */
    public function reinfection_verify( $request ) {
        if ( ! class_exists( '\Nexura_Security\Reinfection_Verifier' ) ) {
            return new \WP_Error( 'module_missing', 'Reinfection Verifier not loaded.', [ 'status' => 500 ] );
        }

        $verifier = new Reinfection_Verifier();
        $file_path = sanitize_text_field( $request->get_param( 'path' ) );

        if ( ! empty( $file_path ) ) {
            $result = $verifier->verify_file( $file_path );
        } else {
            $result = $verifier->verify_all();
        }

        return rest_ensure_response( [ 'success' => true, 'data' => $result ] );
    }

    /**
     * Reinfection Guard Clear — resets saved investigation results and state.
     */
    public function reinfection_clear( $request ) {
        delete_option( 'NEXURA_reinfection_result' );
        delete_option( 'NEXURA_reinfection_state' );
        return rest_ensure_response( [ 'success' => true, 'message' => 'Investigation results cleared.' ] );
    }

    /**
     * Prepare reinfection report for free tier.
     * Full diagnostic findings (file paths, persistence mechanisms) are transparently
     * provided in compliance with WordPress.org Guidelines (Guideline 5: No Crippleware).
     * Automated remediation and quarantine remain strictly protected behind Pro checks.
     *
     * @param array $report
     * @return array
     */
    private function mask_reinfection_report_for_free( $report ) {
        return $report;
    }

}



