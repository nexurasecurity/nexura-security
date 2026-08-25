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

    }

    /**
     * Checks permissions for REST API requests.
     *
     * @return bool|\WP_Error
     */
    public function check_permissions() {
        if ( ! current_user_can( 'manage_options' ) ) {
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
            // Block access to sensitive configuration files
            if ( basename( $real_path ) === 'wp-config.php' || basename( $real_path ) === 'wp-config-sample.php' ) {
                return false;
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
            return new \WP_Error( 'pro_required', 'Vulnerability Audit requires Pro.', [ 'status' => 403 ] );
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
            return new \WP_Error( 'pro_required', 'Auto-Updating vulnerabilities requires Pro.', [ 'status' => 403 ] );
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
            return new \WP_Error( 'pro_required', 'Third Party Audit requires Pro.', [ 'status' => 403 ] );
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
            return new \WP_Error( 'pro_required', 'Performance Audit requires Pro.', [ 'status' => 403 ] );
        }
        $audit = new Performance_Audit();
        $response = $audit->run_audit();
        return rest_ensure_response( [ 'success' => true, 'data' => $response ] );
    }


}
