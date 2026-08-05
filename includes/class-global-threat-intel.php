<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Global_Threat_Intel {

    private $api_url = 'https://sgs-db-worker.sentinel-guard-security.workers.dev';
    private $api_key;

    public function __construct() {
        $this->api_key = get_option( 'NEXURA_license_key', '' );
        
        // Only register remote sync hooks if the user has opted in to Threat Intelligence.
        // This setting is OFF by default to comply with WordPress.org Guidelines 7 & 9.
        if ( get_option( 'NEXURA_enable_threat_intel', '0' ) === '1' ) {
            // Sync cron
            add_action( 'NEXURA_sync_threat_intel', [ $this, 'sync_blocklist' ] );
            add_action( 'admin_init', [ $this, 'schedule_cron' ] );
        }

        // IP reputation check uses local DB only (no remote call), safe to always run.
        add_action( 'plugins_loaded', [ $this, 'check_ip_reputation' ], 5 );
    }

    public function schedule_cron() {
        // Double-check opt-in before scheduling.
        if ( get_option( 'NEXURA_enable_threat_intel', '0' ) !== '1' ) {
            wp_clear_scheduled_hook( 'NEXURA_sync_threat_intel' );
            return;
        }
        if ( ! wp_next_scheduled( 'NEXURA_sync_threat_intel' ) ) {
            wp_schedule_event( time(), 'hourly', 'NEXURA_sync_threat_intel' );
        }
    }

    public function sync_blocklist() {
        // Require opt-in before making any remote API calls.
        if ( get_option( 'NEXURA_enable_threat_intel', '0' ) !== '1' ) {
            return;
        }

        $response = wp_remote_get( $this->api_url . '/blocked-ips', [
            'headers' => [ 'Authorization' => 'Bearer ' . $this->api_key ],
            'timeout' => 10,
        ] );

        if ( ! is_wp_error( $response ) ) {
            $body = wp_remote_retrieve_body( $response );
            $data = json_decode( $body, true );
            
            if ( ! empty( $data['success'] ) && ! empty( $data['data'] ) ) {
                global $wpdb;
                $table_name = $wpdb->prefix . 'NEXURA_threat_ips';
                
                // Clear old list
                $wpdb->query( "DELETE FROM {$table_name}" ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                
                foreach ( $data['data'] as $item ) {
                    $wpdb->insert( $table_name, [ // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
                        'ip_address'   => sanitize_text_field( $item['ip_address'] ),
                        'threat_score' => (int) $item['threat_score'],
                        'updated_at'   => current_time( 'mysql' )
                    ] );
                }
                
                // Cleanup old option
                delete_option( 'NEXURA_global_blocklist' );
            }
        }

        // Also sync malicious domains and patterns from Cloudflare/Threat Intel API
        $this->sync_domains();
    }

    private function sync_domains() {
        // Explicit opt-in guard — this method makes remote API calls.
        // Satisfies WordPress.org Guidelines 7 & 9.
        if ( get_option( 'NEXURA_enable_threat_intel', '0' ) !== '1' ) {
            return;
        }

        $response = wp_remote_get( $this->api_url . '/suspicious-domains', [ 
            'headers' => [ 'Authorization' => 'Bearer ' . $this->api_key ],
            'timeout' => 10 
        ] );
        if ( ! is_wp_error( $response ) ) {
            $body = wp_remote_retrieve_body( $response );
            $data = json_decode( $body, true );
            if ( ! empty( $data['success'] ) && ! empty( $data['domains'] ) ) {
                $upload_dir = wp_upload_dir();
                $data_dir = $upload_dir['basedir'] . '/nexura-security/data';
                if ( ! is_dir( $data_dir ) ) wp_mkdir_p( $data_dir );
                require_once ABSPATH . 'wp-admin/includes/file.php';
                WP_Filesystem();
                global $wp_filesystem;
                $wp_filesystem->put_contents( $data_dir . '/suspicious-domains.json', wp_json_encode( $data['domains'] ), FS_CHMOD_FILE );
            }
        }

        $response_patterns = wp_remote_get( $this->api_url . '/blacklist-patterns', [ 
            'headers' => [ 'Authorization' => 'Bearer ' . $this->api_key ],
            'timeout' => 10 
        ] );
        if ( ! is_wp_error( $response_patterns ) ) {
            $body = wp_remote_retrieve_body( $response_patterns );
            $data = json_decode( $body, true );
            if ( ! empty( $data['success'] ) && ! empty( $data['patterns'] ) ) {
                $upload_dir = wp_upload_dir();
                $data_dir = $upload_dir['basedir'] . '/nexura-security/data';
                if ( ! is_dir( $data_dir ) ) wp_mkdir_p( $data_dir );
                require_once ABSPATH . 'wp-admin/includes/file.php';
                WP_Filesystem();
                global $wp_filesystem;
                $wp_filesystem->put_contents( $data_dir . '/google-blacklist-patterns.json', wp_json_encode( $data['patterns'] ), FS_CHMOD_FILE );
            }
        }
        
        $this->sync_cloudflare_ips();
    }

    private function sync_cloudflare_ips() {
        $ipv4_response = wp_remote_get( 'https://www.cloudflare.com/ips-v4', [ 'timeout' => 10 ] );
        $ipv6_response = wp_remote_get( 'https://www.cloudflare.com/ips-v6', [ 'timeout' => 10 ] );
        
        $cf_ips = [];
        
        if ( ! is_wp_error( $ipv4_response ) && wp_remote_retrieve_response_code( $ipv4_response ) === 200 ) {
            $ipv4_body = wp_remote_retrieve_body( $ipv4_response );
            $cf_ips = array_merge( $cf_ips, array_filter( array_map( 'trim', explode( "\n", $ipv4_body ) ) ) );
        }
        
        if ( ! is_wp_error( $ipv6_response ) && wp_remote_retrieve_response_code( $ipv6_response ) === 200 ) {
            $ipv6_body = wp_remote_retrieve_body( $ipv6_response );
            $cf_ips = array_merge( $cf_ips, array_filter( array_map( 'trim', explode( "\n", $ipv6_body ) ) ) );
        }
        
        if ( ! empty( $cf_ips ) ) {
            // Save as an array in a PHP file for ultra-fast reading by the standalone WAF
            $upload_dir = wp_upload_dir();
            $log_dir = $upload_dir['basedir'] . '/nexura-logs';
            if ( ! is_dir( $log_dir ) ) wp_mkdir_p( $log_dir );
            
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export
            $file_content = "<?php\n// Auto-generated Cloudflare IPs\nreturn " . var_export( $cf_ips, true ) . ";\n";
            require_once ABSPATH . 'wp-admin/includes/file.php';
            WP_Filesystem();
            global $wp_filesystem;
            $wp_filesystem->put_contents( $log_dir . '/cloudflare-ips.php', $file_content, FS_CHMOD_FILE );
        }
    }

    public function check_ip_reputation() {
        if ( is_admin() && current_user_can( 'manage_options' ) ) {
            return;
        }

        $ip = $this->get_client_ip();
        if ( ! $ip ) return;

        global $wpdb;
        $table_name = $wpdb->prefix . 'NEXURA_threat_ips';
        
        // Fast query instead of loading a massive array into memory
        $score = $wpdb->get_var( $wpdb->prepare( "SELECT threat_score FROM {$table_name} WHERE ip_address = %s", $ip ) ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        
        if ( $score !== null ) {
            $score = (int) $score;
            
            if ( $score > 90 ) {
                // Hard Block
                if ( class_exists( '\Nexura_Security\Attack_Logger' ) ) {
                    \Nexura_Security\Attack_Logger::log_attack( $ip, 'Global Threat Network (Bot/Malicious IP)', 'Blocked' );
                }
                wp_die( '<h1>Access Denied</h1><p>Your IP address is blocked by the Nexura Global Threat Network.</p>', 'Security Block', [ 'response' => 403 ] );
            } elseif ( $score >= 50 ) {
                // CAPTCHA Challenge
                $this->show_challenge_page( $ip );
            }
        }
    }

    private function show_challenge_page( $ip ) {
        // If it's a POST request from the challenge page, verify it
        if ( isset( $_POST['NEXURA_captcha_verify'] ) ) {
            if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'NEXURA_captcha_challenge' ) ) {
                wp_die( esc_html__( 'Security check failed.', 'nexura-security' ) );
            }
            if ( $this->verify_captcha() ) {
                // Mark as verified for this session
                setcookie( 'NEXURA_verified_ip', md5($ip . wp_salt()), time() + 3600, '/' );
                $redirect_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/';
                wp_safe_redirect( esc_url_raw( $redirect_uri ) );
                exit;
            }
        }

        // If verified, allow
        if ( isset( $_COOKIE['NEXURA_verified_ip'] ) && $_COOKIE['NEXURA_verified_ip'] === md5($ip . wp_salt()) ) {
            return;
        }

        $site_key = get_option( 'NEXURA_captcha_site_key', '' );
        $captcha_type = get_option( 'NEXURA_captcha_type', 'turnstile' );

        if ( empty( $site_key ) ) {
            // No captcha set, show generic warning
            wp_die( '<h1>Security Verification Required</h1><p>Your network traffic looks suspicious. The administrator has not configured a CAPTCHA. Please try again later.</p>', 'Verification Required', [ 'response' => 403 ] );
        }

        ob_start();
        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Challenge</title>
            <?php
            wp_enqueue_style( 'nexura-challenge', NEXURA_PLUGIN_URL . 'public/css/challenge.css', [], NEXURA_VERSION );
            wp_print_styles( 'nexura-challenge' );
            
            if ( $captcha_type === 'turnstile' ) {
                // phpcs:ignore WordPress.WP.EnqueuedResourceParameters.MissingVersion, PluginCheck.CodeAnalysis.EnqueuedResourceOffloading.OffloadedContent
                wp_enqueue_script( 'cloudflare-turnstile', 'https://challenges.cloudflare.com/turnstile/v0/api.js', [], null, true );
                wp_print_scripts( 'cloudflare-turnstile' );
            } elseif ( $captcha_type === 'recaptcha' ) {
                // google.com/recaptcha is only loaded when the administrator has explicitly
                // chosen reCAPTCHA as the CAPTCHA provider in the plugin settings.
                // This is a 100% opt-in, user-configured external service.
                // phpcs:ignore WordPress.WP.EnqueuedResourceParameters.MissingVersion, PluginCheck.CodeAnalysis.EnqueuedResourceOffloading.OffloadedContent
                wp_enqueue_script( 'google-recaptcha', 'https://www.google.com/recaptcha/api.js', [], null, true );
                wp_print_scripts( 'google-recaptcha' );
            }
            ?>
        </head>
        <body>
            <div class="card">
                <h1>Security Challenge</h1>
                <p>Your network traffic looks suspicious. Please verify you are human.</p>
                <form method="POST">
                    <?php wp_nonce_field( 'NEXURA_captcha_challenge' ); ?>
                    <?php if ( $captcha_type === 'turnstile' ) : ?>
                        <div class="cf-turnstile" data-sitekey="<?php echo esc_attr( $site_key ); ?>"></div>
                    <?php elseif ( $captcha_type === 'recaptcha' ) : ?>
                        <div class="g-recaptcha" data-sitekey="<?php echo esc_attr( $site_key ); ?>"></div>
                    <?php endif; ?>
                    <button type="submit" name="NEXURA_captcha_verify" class="btn">Verify</button>
                </form>
            </div>
        </body>
        </html>
        <?php
        $html = ob_get_clean();
        echo $html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        exit;
    }

    private function verify_captcha() {
        $secret = get_option( 'NEXURA_captcha_secret_key', '' );
        $type = get_option( 'NEXURA_captcha_type', 'turnstile' );

        if ( $type === 'turnstile' && isset( $_POST['cf-turnstile-response'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $response = wp_remote_post( 'https://challenges.cloudflare.com/turnstile/v0/siteverify', [
                'body' => [
                    'secret'   => $secret,
                    'response' => sanitize_text_field( wp_unslash( $_POST['cf-turnstile-response'] ) ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
                    'remoteip' => $this->get_client_ip()
                ]
            ]);
            if ( ! is_wp_error( $response ) ) {
                $body = json_decode( wp_remote_retrieve_body( $response ), true );
                return ! empty( $body['success'] );
            }
        } elseif ( $type === 'recaptcha' && isset( $_POST['g-recaptcha-response'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
            // google.com/recaptcha/api/siteverify is only called when the administrator has
            // explicitly configured reCAPTCHA as the CAPTCHA provider (opt-in service).
            $response = wp_remote_post( 'https://www.google.com/recaptcha/api/siteverify', [
                'body' => [
                    'secret'   => $secret,
                    'response' => sanitize_text_field( wp_unslash( $_POST['g-recaptcha-response'] ) ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
                    'remoteip' => $this->get_client_ip()
                ]
            ]);
            if ( ! is_wp_error( $response ) ) {
                $body = json_decode( wp_remote_retrieve_body( $response ), true );
                return ! empty( $body['success'] );
            }
        }
        return false;
    }

    public function report_ip( $reason ) {
        // Enforce opt-in requirement for phoning home
        if ( ! get_option( 'NEXURA_share_threat_data', false ) ) {
            return;
        }

        $ip = $this->get_client_ip();
        if ( ! $ip || in_array( $ip, [ '127.0.0.1', '::1', 'localhost' ], true ) ) return;

        wp_remote_post( $this->api_url . '/report-ip', [
            'headers' => [ 'Content-Type' => 'application/json', 'Authorization' => 'Bearer ' . $this->api_key ],
            'body'    => wp_json_encode([
                'ip_address'  => $ip,
                'reason'      => $reason,
                'reported_by' => wp_parse_url( site_url(), PHP_URL_HOST )
            ]),
            'timeout' => 5,
        ] );
    }

    private function get_client_ip() {
        $ip = '127.0.0.1';
        if ( isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
            $ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
        } elseif ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
            $ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
        }
        return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '127.0.0.1';
    }
}
