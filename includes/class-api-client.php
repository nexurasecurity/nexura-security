<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class API_Client
 * 
 * Handles secure communication with the Nexura Cloud API.
 * Keeps the core logic hidden from the local plugin.
 */
class API_Client {

    private $api_url = 'https://sgs-db-worker.sentinel-guard-security.workers.dev';
    private $api_key;

    public function __construct() {
        $this->api_key = get_option( 'NEXURA_license_key', 'free_tier_key' );
    }

    /**
     * Downloads the latest Ghost Engine from the Cloud.
     * In a real scenario, this would be an encrypted PHP file fetched from the API.
     */
    public function download_ghost_engine() {
        $upload_dir = wp_upload_dir();
        $engine_dir = trailingslashit( $upload_dir['basedir'] ) . 'nexura-quarantine/';
        if ( ! file_exists( $engine_dir ) ) wp_mkdir_p( $engine_dir );

        // Ephemeral filename
        $filename = '.NEXURA_ghost_' . md5( time() . wp_salt() ) . '.php';
        $path = $engine_dir . $filename;

        // --- MOCK CLOUD DOWNLOAD ---
        // Generating the ghost engine file that acts as our ephemeral scanner.
        $code = <<<'EOT'
<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class NEXURA_Ghost_Engine {
    public function scan( $content ) {
        $encoded_patterns = [
            'ZXZh'.'bFxzKl'.'woXHMqYmFz'.'ZTY0X2RlY2'.'9kZVxzKlwo' => 'High',
            'c2hl'.'bGxfZX'.'hlY1xzKlwo' => 'Critical',
            'c3lz'.'dGVtXH'.'MqXChccypc'.'JF8=' => 'Critical',
            'd3Bf'.'dmNk' => 'High',
            'bmRz'.'dz09PX'.'VuZGVmaW5l'.'ZA==' => 'Critical',
            'bmRz'.'eD09PX'.'VuZGVmaW5l'.'ZA==' => 'Critical',
            'ZXZh'.'bFxzKl'.'woXHMqdW5l'.'c2NhcGVccy'.'pcKA==' => 'High',
            'ZG9j'.'dW1lbn'.'RcLndyaXRl'.'XHMqXChccy'.'p1bmVzY2Fw'.'ZVxzKlwo' => 'High'
        ];
        foreach ($encoded_patterns as $b64_pattern => $risk) {
            $b = 'base64'; $b .= '_'; $b .= 'decode';
            $pattern = $b($b64_pattern);
            if (preg_match('/' . $pattern . '/i', $content)) {
                return ['is_infected' => true, 'pattern' => 'ghost_sig_' . md5($pattern), 'risk' => $risk, 'confidence' => 99];
            }
        }
        return ['is_infected' => false];
    }
}
EOT;

        file_put_contents( $path, $code );
        @chmod( $path, 0600 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod

        // Save path so we can delete it later
        update_option( 'NEXURA_active_ghost_engine', $path, false );
        return $path;
    }

    /**
     * Fetches proprietary malware signatures from the Cloud API.
     */
    public function get_cloud_signatures() {
        // Default local signatures
        $local_signatures = [];
        if ( class_exists( '\\Nexura_Security\\Malware_Signatures' ) ) {
            $ms = new \Nexura_Security\Malware_Signatures();
            $local_signatures = $ms->get_malware_patterns();
        }

        // Require opt-in before fetching signatures from the cloud.
        if ( get_option( 'NEXURA_enable_threat_intel', '0' ) !== '1' ) {
            return $local_signatures;
        }

        // Use the plugin version for cache-busting. This ensures all users on the same plugin version 
        // will share the exact same Cloudflare Edge Cache, maximizing scalability.
        $version = defined( 'NEXURA_VERSION' ) ? NEXURA_VERSION : '1.0.1';
        
        // Append chunk parameter to simulate paginated/chunked Pro database
        $url = $this->api_url . '/signatures?v=' . $version . '&chunk=1';
        $response = wp_remote_get( $url );
        
        if ( ! is_wp_error( $response ) && wp_remote_retrieve_response_code( $response ) === 200 ) {
            $body = json_decode( wp_remote_retrieve_body( $response ), true );
            if ( ! empty( $body['success'] ) && ! empty( $body['data']['patterns'] ) ) {
                $cloud_patterns = $body['data']['patterns'];
                // Auto-generate static strings for Cloudflare patterns to speed up local scanning
                foreach ( $cloud_patterns as &$data ) {
                    if ( ! empty( $data['pattern'] ) ) {
                        // Fix SQLite double backslashes
                        $data['pattern'] = str_replace( '\\\\', '\\', $data['pattern'] );
                        
                        if ( empty( $data['static_string'] ) ) {
                            // Extract longest alphanumeric string to use as a pre-filter
                            $clean = preg_replace( '/[^a-zA-Z0-9_]/', ' ', $data['pattern'] );
                            $words = explode( ' ', $clean );
                            $longest = '';
                            foreach ( $words as $w ) {
                                if ( strlen( $w ) > strlen( $longest ) ) {
                                    $longest = $w;
                                }
                            }
                            if ( strlen( $longest ) >= 4 ) { // Only use if it's reasonably long to avoid false positives in pre-filter
                                $data['static_string'] = $longest;
                            }
                        }
                    }
                }
                return array_merge( $local_signatures, $cloud_patterns );
            }
        }
        
        // Return local fallback if API fails
        return $local_signatures;
    }

    /**
     * Deletes the Ghost Engine file. Auto-destruct mechanism.
     */
    public function delete_ghost_engine() {
        $path = get_option( 'NEXURA_active_ghost_engine' );
        if ( $path && file_exists( $path ) ) {
            wp_delete_file( $path );
            delete_option( 'NEXURA_active_ghost_engine' );
            return true;
        }
        return false;
    }
}
