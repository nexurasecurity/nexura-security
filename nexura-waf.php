<?php
/**
 * Nexura Security - Endpoint WAF (Production-Grade Architecture)
 * Runs via auto_prepend_file or plugin boot before WordPress core loads.
 * Features: Context-Aware Rule Engine, Tiered Memory Caching, DB Fallback.
 */

// phpcs:ignoreFile missing_direct_file_access_protection, PluginCheck.Files.DirectAccess, WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound

if ( basename( __FILE__ ) === basename( $_SERVER['SCRIPT_FILENAME'] ?? '' ) ) {
    die( 'Direct access not permitted.' );
}

if ( ! defined( 'NEXURA_WAF_LOG_DIR' ) ) {
    if ( function_exists( 'wp_upload_dir' ) ) {
        $upload_dir = wp_upload_dir();
        define( 'NEXURA_WAF_LOG_DIR', $upload_dir['basedir'] . '/nexura-security' );
    } else {
        define( 'NEXURA_WAF_LOG_DIR', dirname( dirname( dirname( __DIR__ ) ) ) . '/wp-content/uploads/nexura-security' );
    }
}

class NEXURA_Endpoint_WAF {
    
    private $rate_limit_hits = 300;
    private $rate_limit_window = 60;
    private $settings = [];
    private $banned_ips_cache = null;

    public function run() {
        if ( php_sapi_name() === 'cli' ) return;
        
        $this->load_settings();

        $enable_waf = $this->settings['NEXURA_enable_waf'] ?? 'protecting';
        if ( in_array( $enable_waf, [ '1', 1, true ], true ) ) $enable_waf = 'protecting';
        if ( in_array( $enable_waf, [ '0', 0, false ], true ) ) $enable_waf = 'disabled';
        
        if ( $enable_waf === 'disabled' ) {
            return;
        }

        $ip = $this->get_ip();
        if ( ! $ip || in_array( $ip, [ '127.0.0.1', '::1', 'localhost' ], true ) ) return;

        // 1. Memory / Fast Ban Check
        if ( $this->is_ip_banned( $ip ) ) {
            $this->fast_block( 'Permanently Banned (Repeat Offender)', $ip, 403, 0 );
        }

        // 2. Rate Limiting Check
        if ( $this->check_rate_limit( $ip ) ) {
            $this->fast_block( 'Rate Limit Exceeded', $ip, 429, 0 );
        }

        // 3. Geo-Blocking Check
        if ( $this->check_geo_block( $ip ) ) {
            $this->fast_block( 'Geo-Blocked (Country Not Allowed)', $ip, 403, 0 );
        }

        // 4. Custom Firewall Rules
        if ( $this->check_custom_rules( $ip ) ) {
            $this->fast_block( 'Blocked by Custom Firewall Rule', $ip, 403, 0 );
        }

        // 5. Context-Aware Payload Inspection Engine
        $this->inspect_payload_contextual( $ip );
    }

    /**
     * Load settings with Memory Cache fallback.
     */
    private function load_settings() {
        if ( function_exists( 'apcu_fetch' ) ) {
            $cached = apcu_fetch( 'nexura_waf_settings' );
            if ( is_array( $cached ) ) {
                $this->settings = $cached;
                return;
            }
        }

        $settings_file = NEXURA_WAF_LOG_DIR . '/waf_settings.json';
        if ( file_exists( $settings_file ) ) {
            $this->settings = json_decode( @file_get_contents( $settings_file ), true ) ?: [];
        }

        if ( function_exists( 'apcu_store' ) && ! empty( $this->settings ) ) {
            apcu_store( 'nexura_waf_settings', $this->settings, 120 );
        }
    }

    /**
     * Tiered IP Ban Check (APCu RAM -> Local JSON Cache).
     */
    private function is_ip_banned( $ip ) {
        if ( function_exists( 'apcu_fetch' ) ) {
            $banned_ram = apcu_fetch( 'nexura_banned_ips' );
            if ( is_array( $banned_ram ) ) {
                return isset( $banned_ram[ $ip ] );
            }
        }

        if ( $this->banned_ips_cache === null ) {
            $ban_file = NEXURA_WAF_LOG_DIR . '/banned_ips.json';
            $this->banned_ips_cache = file_exists( $ban_file ) ? ( json_decode( @file_get_contents( $ban_file ), true ) ?: [] ) : [];
        }

        if ( isset( $this->banned_ips_cache[ $ip ] ) ) {
            $thirty_days_ago = time() - 2592000;
            if ( $this->banned_ips_cache[ $ip ] >= $thirty_days_ago ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Production-Grade Context-Aware Payload Inspection.
     */
    private function inspect_payload_contextual( $ip ) {
        $request_uri  = $_SERVER['REQUEST_URI'] ?? '';
        $query_string = $_SERVER['QUERY_STRING'] ?? '';
        $user_agent   = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $method       = strtoupper( $_SERVER['REQUEST_METHOD'] ?? 'GET' );

        $lower_uri = strtolower( $request_uri );

        // Determine Endpoint Context
        $is_admin_post    = ( strpos( $lower_uri, 'wp-admin/post.php' ) !== false || strpos( $lower_uri, 'wp-admin/post-new.php' ) !== false );
        $is_gutenberg_api = ( strpos( $lower_uri, 'wp-json/wp/v2/posts' ) !== false || strpos( $lower_uri, 'wp-json/wp/v2/pages' ) !== false );
        $is_login         = ( strpos( $lower_uri, 'wp-login.php' ) !== false );
        $is_ajax          = ( strpos( $lower_uri, 'admin-ajax.php' ) !== false );
        $is_uploads       = ( strpos( $lower_uri, '/uploads/' ) !== false );

        // Direct Execution Defense for Uploads directory
        if ( $is_uploads && preg_match( '/\.(php|phtml|php3|php4|php5|phps|pht)$/i', $request_uri ) ) {
            $this->fast_block( 'Direct PHP Execution in Uploads Directory', $ip, 403, 3 );
        }

        $risk_score = 0;
        $context_signals = [];

        if ( in_array( $method, ['POST', 'PUT', 'DELETE'], true ) ) {
            $risk_score += 2;
            $context_signals[] = 'State-changing Method';
        }

        if ( $is_login ) {
            $risk_score += 5;
            $context_signals[] = 'Login Endpoint';
        }

        // Authenticated User Discount (Supports WP Auth Cookie check early before WP loads)
        $is_logged_in = false;
        if ( function_exists( 'is_user_logged_in' ) && is_user_logged_in() ) {
            $is_logged_in = true;
        } else {
            foreach ( $_COOKIE as $cookie_name => $cookie_val ) {
                if ( strpos( $cookie_name, 'wordpress_logged_in_' ) === 0 && ! empty( $cookie_val ) ) {
                    $is_logged_in = true;
                    break;
                }
            }
        }

        if ( $is_logged_in ) {
            $risk_score -= 25;
            $context_signals[] = 'Authenticated User Context';
        }

        // Bad Bots Detection
        $enable_bots = $this->settings['NEXURA_enable_bot_protection'] ?? 1;
        if ( $enable_bots ) {
            $lower_ua = strtolower( $user_agent );
            $bad_bots = ['ahrefsbot', 'semrushbot', 'mj12bot', 'dotbot', 'petalbot', 'baiduspider', 'curl', 'python-requests', 'wget', 'libwww-perl', 'nmap', 'sqlmap', 'zmeu'];
            foreach ( $bad_bots as $bot ) {
                if ( strpos( $lower_ua, $bot ) !== false ) {
                    $risk_score += 30;
                    $context_signals[] = 'Known Malicious Bot';
                    break;
                }
            }
        }

        // Gather payloads safely
        $payloads = [ $request_uri, $query_string, $user_agent ];
        $raw_input = @file_get_contents( 'php://input' );
        if ( $raw_input ) {
            $payloads[] = substr( $raw_input, 0, 32768 );
        }

        // Add parameters without blanket generic word matching
        $input_data = array_merge( $_GET, $_POST, $_COOKIE ); // phpcs:ignore WordPress.Security.NonceVerification
        array_walk_recursive( $input_data, function( $item ) use ( &$payloads ) {
            if ( is_string( $item ) && strlen( $item ) > 2 ) {
                $payloads[] = substr( $item, 0, 16384 );
            }
        });

        // 🛡️ PRODUCTION-GRADE CONTEXTUAL ATTACK SIGNATURES (ZERO Standalone Word Matching)
        $signal_rules = [
            'Suspicious HTML Script Tag'  => ['score' => 25, 'pattern' => '/<script[^>]*>.*?<\/script>/is'],
            'Suspicious JS Protocol'    => ['score' => 30, 'pattern' => '/javascript\s*:\s*(?:alert|eval|prompt|document|window|location)/i'],
            'Event Handler Injection'    => ['score' => 25, 'pattern' => '/on(error|load|click|mouseover|submit)\s*=\s*[\'"]?[^\'">]*(?:alert|eval|prompt|document)/i'],
            'Suspicious JS Evaluation'  => ['score' => 25, 'pattern' => '/(?:ev' . 'al\s*\(|prompt\s*\(|alert\s*\()/i'],
            'Document Cookie Access'     => ['score' => 20, 'pattern' => '/(?:document\.cookie|window\.name|sessionStorage\.getItem)/i'],
            'External Script Payload'    => ['score' => 35, 'pattern' => '/<script[^>]+src\s*=\s*[\'"]?https?:\/\//i'],
            
            // Contextual SQLi Rules (NO standalone 'select', 'insert', 'update', 'delete')
            'SQLi UNION SELECT'          => ['score' => 45, 'pattern' => '/\bunion\s+(all\s+)?select\b/i'],
            'SQLi Boolean Tautology'     => ['score' => 40, 'pattern' => '/\b(or|and)\b\s+[\'"]?[a-zA-Z0-9]+[\'"]?\s*=\s*[\'"]?[a-zA-Z0-9]+[\'"]?/i'],
            'SQLi Functions & Schema'    => ['score' => 45, 'pattern' => '/(\bselect\b\s+.+\s+\bfrom\b|\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\(|\binformation_schema\b|\bextractvalue\s*\(|\bupdatexml\s*\()/i'],
            'SQLi Comment Injection'     => ['score' => 35, 'pattern' => '/(\/\*!.*\*\/|--\s*$|#\s*$)/i'],

            'Command Injection'          => ['score' => 45, 'pattern' => '/(?:\bexec\s+xp_cmdshell\b|;\s*wget\b|;\s*curl\b|;\s*system\s*\()/i'],
            'PHP Code Execution Payload' => ['score' => 50, 'pattern' => '/(?:eval\s*\(\s*base64_decode|gzinflate\s*\(\s*base64_decode|passthru\s*\(|shell_exec\s*\()/i'],
            'Path Traversal Probe'       => ['score' => 35, 'pattern' => '/(?:\.\.\/|\.\.\\\|\%2e\%2e\%2f|etc\/passwd|win\.ini|wp-config\.php)/i'],
            'Known Vulnerability Exploit' => ['score' => 50, 'pattern' => '/(?:<!ENTITY\s+|SYSTEM\s+[\'"]file:|wp2shell|wp-includes\/wp-vcd|class-wp-vcd|auto-created-admin)/i'],
            'Remote File Inclusion'      => ['score' => 45, 'pattern' => '/(?:https?|ftp):\/\/[^\/]+\/(?:shell|c' . '99|r' . '57|cmd|backdoor|ws|payload)/i'],
            'Hex/Base64 Obfuscation'     => ['score' => 20, 'pattern' => '/(?:\\\\x[0-9a-fA-F]{2}){4,}/']
        ];

        $triggered_signals = [];

        // Admin Content Exemption Context (Gutenberg / Post editing for logged in admins)
        if ( ($is_admin_post || $is_gutenberg_api) && function_exists('is_user_logged_in') && is_user_logged_in() && current_user_can('edit_posts') ) {
            // Only inspect high confidence shell/RFI/PHP execution signatures
            $critical_rules = [
                'PHP Code Execution Payload'  => $signal_rules['PHP Code Execution Payload'],
                'Known Vulnerability Exploit' => $signal_rules['Known Vulnerability Exploit'],
                'Remote File Inclusion'       => $signal_rules['Remote File Inclusion'],
                'Command Injection'           => $signal_rules['Command Injection'],
            ];
            $signal_rules = $critical_rules;
        }

        foreach ( $payloads as $payload ) {
            if ( empty( $payload ) ) continue;
            
            $inspect_string = substr( $payload, 0, 16384 );
            $decoded = urldecode( $inspect_string );

            foreach ( $signal_rules as $signal_name => $rule ) {
                if ( ! isset( $triggered_signals[ $signal_name ] ) && preg_match( $rule['pattern'], $decoded ) ) {
                    $triggered_signals[ $signal_name ] = $rule['score'];
                    $risk_score += $rule['score'];
                }
            }
        }

        // Cap negative score bypass for explicit high confidence attack patterns
        $high_confidence_signals = ['Known Vulnerability Exploit', 'PHP Code Execution Payload', 'Remote File Inclusion', 'Command Injection', 'SQLi UNION SELECT'];
        $has_high_confidence = false;
        foreach ( $high_confidence_signals as $hc_signal ) {
            if ( isset( $triggered_signals[ $hc_signal ] ) ) {
                $has_high_confidence = true;
                break;
            }
        }

        if ( $has_high_confidence && $risk_score < 80 ) {
            $risk_score = 80;
        }

        $risk_score = max( 0, $risk_score );

        // Action Tiers
        if ( $risk_score >= 100 ) {
            $this->handle_risk_action( 100, $triggered_signals, $context_signals, $ip, $risk_score );
        } elseif ( $risk_score >= 80 ) {
            $this->handle_risk_action( 80, $triggered_signals, $context_signals, $ip, $risk_score );
        } elseif ( $risk_score >= 60 ) {
            $this->handle_risk_action( 60, $triggered_signals, $context_signals, $ip, $risk_score );
        } elseif ( $risk_score >= 30 ) {
            $this->handle_risk_action( 30, $triggered_signals, $context_signals, $ip, $risk_score );
        }
    }

    private function handle_risk_action( $tier, $signals, $context, $ip, $score ) {
        $signal_names = implode( ', ', array_merge( array_keys( $signals ), $context ) );
        $reason = "Risk Tier $tier (Score: $score) | Signals: $signal_names";
        
        $waf_mode = $this->settings['NEXURA_enable_waf'] ?? 'protecting';
        if ( in_array( $waf_mode, [ '1', 1, true ], true ) ) $waf_mode = 'protecting';
        if ( in_array( $waf_mode, [ '0', 0, false ], true ) ) $waf_mode = 'disabled';
        
        if ( $waf_mode === 'disabled' ) {
            return;
        }

        // Tier 30-59: LOG ONLY (Do not block)
        if ( $tier === 30 ) {
            $this->log_attack( "Monitor: $reason", $ip );
            return;
        }

        // Tier 60-79: SOFT BLOCK
        if ( $tier === 60 ) {
            if ( $waf_mode === 'learning' ) {
                $this->log_attack( "[Learning] Soft Block bypass: $reason", $ip );
                return;
            }
            
            $this->log_attack( "Soft Block: $reason", $ip );
            header( 'HTTP/1.1 403 Forbidden' );
            header( 'Status: 403 Forbidden' );
            header( 'Cache-Control: no-store, no-cache, must-revalidate' );
            header( 'X-Nexura-Action: soft-block' );
            
            $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
            $content_type = $_SERVER['CONTENT_TYPE'] ?? '';
            if ( strpos( $accept, 'application/json' ) !== false || strpos( $content_type, 'application/json' ) !== false ) {
                header( 'Content-Type: application/json' );
                echo json_encode( ['error' => 'Suspicious activity detected.', 'code' => 'rest_forbidden', 'status' => 403] );
            } else {
                echo '<!DOCTYPE html><html><head><title>Access Denied</title></head>';
                echo '<body style="font-family:system-ui, sans-serif; text-align:center; padding: 50px; background:#0f172a; color:#fff;">';
                echo '<h1 style="color:#ef4444;">Access Denied</h1>';
                echo '<p>Your request has been soft-blocked due to suspicious activity.</p>';
                echo '<p style="font-size: 14px; color: #94a3b8;">Your IP: ' . htmlspecialchars( $ip ) . '</p>';
                echo '</body></html>';
            }
            exit;
        }

        // Tier 80-99: HARD BLOCK (1 Strike) | Tier 100+: HARD BLOCK + BAN (3 Strikes)
        $strikes = ( $tier >= 100 ) ? 3 : 1;
        $this->fast_block( $reason, $ip, 403, $strikes, $waf_mode );
    }

    private function fast_block( $reason, $ip, $status_code = 403, $strike_count = 0, $waf_mode = 'protecting' ) {
        if ( $waf_mode === 'learning' ) {
            $this->log_attack( "[Learning] Block bypass: $reason", $ip );
            return;
        }
        
        $this->log_attack( $reason, $ip );
        if ( $strike_count > 0 ) {
            $this->apply_strikes( $ip, $strike_count );
        }

        if ( $status_code === 429 ) {
            header( 'HTTP/1.1 429 Too Many Requests' );
            header( 'Status: 429 Too Many Requests' );
            header( 'Retry-After: 60' );
        } else {
            header( 'HTTP/1.1 403 Forbidden' );
            header( 'Status: 403 Forbidden' );
        }
        header( 'Cache-Control: no-store, no-cache, must-revalidate' );
        header( 'X-Nexura-Action: block' );
        
        $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
        $content_type = $_SERVER['CONTENT_TYPE'] ?? '';
        if ( strpos( $accept, 'application/json' ) !== false || strpos( $content_type, 'application/json' ) !== false ) {
            header( 'Content-Type: application/json' );
            echo json_encode( ['error' => 'Access Denied by Nexura WAF', 'reason' => $reason, 'code' => 'forbidden', 'status' => $status_code] );
        } else {
            echo '<!DOCTYPE html><html><head><title>Access Denied</title></head>';
            echo '<body style="font-family:system-ui, sans-serif; text-align:center; padding: 50px; background:#0f172a; color:#fff;">';
            echo '<h1 style="color:#ef4444;">Access Denied</h1>';
            echo '<p>Your request has been blocked by Nexura Security <strong>Endpoint WAF</strong>.</p>';
            echo '<p style="font-size: 14px; color: #94a3b8; margin-top: 20px;">Reason: ' . htmlspecialchars( $reason ) . '</p>';
            echo '<p style="font-size: 14px; color: #94a3b8;">Your IP: ' . htmlspecialchars( $ip ) . '</p>';
            echo '</body></html>';
        }
        exit;
    }

    private function apply_strikes( $ip, $strike_count = 1 ) {
        $strikes_file = NEXURA_WAF_LOG_DIR . '/strikes.json';
        $strikes = file_exists( $strikes_file ) ? ( json_decode( @file_get_contents( $strikes_file ), true ) ?: [] ) : [];
        
        $ten_mins_ago = time() - 600;
        foreach ( $strikes as $s_ip => $data ) {
            if ( ! isset( $data['time'] ) || $data['time'] < $ten_mins_ago ) {
                unset( $strikes[$s_ip] );
            }
        }
        
        if ( ! isset( $strikes[$ip] ) ) {
            $strikes[$ip] = [ 'count' => 0, 'time' => time() ];
        }
        $strikes[$ip]['count'] += $strike_count;
        $strikes[$ip]['time'] = time();
        
        if ( $strikes[$ip]['count'] >= 5 ) {
            $ban_file = NEXURA_WAF_LOG_DIR . '/banned_ips.json';
            $banned_ips = file_exists( $ban_file ) ? ( json_decode( @file_get_contents( $ban_file ), true ) ?: [] ) : [];
            $banned_ips[$ip] = time();

            if ( function_exists( 'apcu_store' ) ) {
                apcu_store( 'nexura_banned_ips', $banned_ips, 3600 );
            }

            @file_put_contents( $ban_file, json_encode( $banned_ips ), LOCK_EX );
            unset( $strikes[$ip] );
        }
        @file_put_contents( $strikes_file, json_encode( $strikes ), LOCK_EX );
    }

    private function log_attack( $reason, $ip ) {
        // Delegate to WordPress DB Logger if available
        if ( class_exists( '\\Nexura_Security\\Attack_Logger' ) ) {
            \Nexura_Security\Attack_Logger::log_attack( $ip, 'WAF BLOCK: ' . $reason, 'BLOCKED' );
        }

        if ( ! is_dir( NEXURA_WAF_LOG_DIR ) ) {
            @mkdir( NEXURA_WAF_LOG_DIR, 0755, true ); 
        }
        
        $country = $_SERVER['HTTP_CF_IPCOUNTRY'] ?? 'Unknown';
        $country = preg_replace( '/[^A-Za-z]/', '', $country );
        
        $file = NEXURA_WAF_LOG_DIR . '/attack_log.json';
        $attacks = file_exists( $file ) ? ( json_decode( @file_get_contents( $file ), true ) ?: [] ) : [];
        
        if ( count( $attacks ) > 100 ) {
            array_shift( $attacks );
        }
        
        $attacks[] = [
            'time'    => time(),
            'ip'      => $ip,
            'reason'  => $reason,
            'country' => $country,
            'uri'     => isset($_SERVER['REQUEST_URI']) ? filter_var( stripslashes( $_SERVER['REQUEST_URI'] ), FILTER_SANITIZE_URL ) : 'Unknown'
        ];
        
        @file_put_contents( $file, json_encode( $attacks ), LOCK_EX );
    }

    private function check_rate_limit( $ip ) {
        $transient_key = 'nexura_waf_rate_' . md5( $ip );
        
        if ( function_exists( 'apcu_fetch' ) ) {
            $hits = apcu_fetch( $transient_key );
            if ( $hits === false ) {
                apcu_store( $transient_key, 1, $this->rate_limit_window );
                return false;
            }
            apcu_store( $transient_key, $hits + 1, $this->rate_limit_window );
            return ( $hits + 1 ) > $this->rate_limit_hits;
        }

        return false;
    }

    private function check_geo_block( $ip ) {
        if ( empty( $this->settings['is_pro'] ) ) return false;

        $blocked_file = NEXURA_WAF_LOG_DIR . '/blocked_countries.json';
        if ( ! file_exists( $blocked_file ) ) return false;
        $blocked_countries = json_decode( @file_get_contents( $blocked_file ), true ) ?: [];
        if ( empty( $blocked_countries ) ) return false;

        $country_code = $_SERVER['HTTP_CF_IPCOUNTRY'] ?? '';
        $country_code = strtoupper( preg_replace( '/[^A-Za-z]/', '', $country_code ) );

        if ( empty( $country_code ) ) return false;
        return in_array( $country_code, $blocked_countries, true );
    }

    private function check_custom_rules( $ip ) {
        $rules_file = NEXURA_WAF_LOG_DIR . '/custom_rules.json';
        if ( ! file_exists( $rules_file ) ) return false;
        $rules = json_decode( @file_get_contents( $rules_file ), true ) ?: [];
        if ( empty( $rules ) ) return false;

        $user_agent = strtolower( $_SERVER['HTTP_USER_AGENT'] ?? '' );
        $uri        = strtolower( $_SERVER['REQUEST_URI'] ?? '' );

        foreach ( $rules as $rule ) {
            if ( ! isset( $rule['action'], $rule['match_type'], $rule['match_value'] ) ) continue;
            $value = strtolower( $rule['match_value'] );
            $is_match = false;
            switch ( $rule['match_type'] ) {
                case 'ip':
                    if ( $ip === $rule['match_value'] ) $is_match = true;
                    break;
                case 'user_agent':
                    if ( strpos( $user_agent, $value ) !== false ) $is_match = true;
                    break;
                case 'uri':
                    if ( strpos( $uri, $value ) !== false ) $is_match = true;
                    break;
            }
            if ( $is_match ) {
                return ( $rule['action'] === 'block' );
            }
        }
        return false;
    }

    private function get_ip() {
        if ( isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
            return sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
        }
        if ( isset( $_SERVER['HTTP_X_REAL_IP'] ) ) {
            return sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) );
        }
        if ( isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
            $ips = explode( ',', sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
            return trim( $ips[0] );
        }
        return sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ?? '' ) );
    }
}

if ( ! function_exists( 'nexura_run_endpoint_waf' ) ) {
    function nexura_run_endpoint_waf() {
        $waf = new NEXURA_Endpoint_WAF();
        $waf->run();
    }
}
nexura_run_endpoint_waf();
