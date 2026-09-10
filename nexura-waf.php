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
    // Pure PHP path detection — no WordPress API, safe before WP loads.
    // Walk up from: wp-content/plugins/nexura-security/nexura-waf.php
    //           to: wp-content/uploads/nexura-security
    $nexura_waf_uploads = dirname( dirname( dirname( __DIR__ ) ) ) . DIRECTORY_SEPARATOR
        . 'wp-content' . DIRECTORY_SEPARATOR . 'uploads' . DIRECTORY_SEPARATOR . 'nexura-security';
    define( 'NEXURA_WAF_LOG_DIR', $nexura_waf_uploads );
    unset( $nexura_waf_uploads );
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
     *
     * APCu cache is validated against the 30-day expiry on every check so that
     * an IP whose ban has expired in the JSON file is not kept banned indefinitely
     * by a stale APCu entry (which has a 1-hour TTL of its own).
     */
    private function is_ip_banned( $ip ) {
        if ( function_exists( 'apcu_fetch' ) ) {
            $banned_ram = apcu_fetch( 'nexura_banned_ips' );
            if ( is_array( $banned_ram ) && isset( $banned_ram[ $ip ] ) ) {
                // Validate expiry even for cached data to avoid stale bans.
                $thirty_days_ago = time() - 2592000;
                return $banned_ram[ $ip ] >= $thirty_days_ago;
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
        $is_xmlrpc        = ( strpos( $lower_uri, 'xmlrpc.php' ) !== false );

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

        // XML-RPC requests carry higher inherent risk: they tunnel method calls
        // inside XML bodies which bypass standard form-field inspection.
        if ( $is_xmlrpc ) {
            $risk_score += 10;
            $context_signals[] = 'XML-RPC Endpoint';
        }

        // Authenticated User Discount.
        // Only granted when WordPress has fully loaded and can verify the session.
        // We do NOT use the auth cookie here: an attacker can forge
        // 'wordpress_logged_in_*' to reduce their risk score by 25 points,
        // potentially evading detection thresholds (e.g. bringing score from
        // 80 → 55, skipping a hard block entirely).
        $is_logged_in = false;
        if ( function_exists( 'is_user_logged_in' ) && is_user_logged_in() ) {
            $is_logged_in = true;
        }

        if ( $is_logged_in ) {
            $risk_score -= 25;
            $context_signals[] = 'Authenticated User Context';
        }

        // Bad Bots Detection
        $enable_bots = $this->settings['NEXURA_enable_bot_protection'] ?? 1;
        if ( $enable_bots ) {
            $lower_ua = strtolower( $user_agent );
            // Only include bots that are unambiguously malicious or never used by
            // legitimate services. curl/wget/python-requests are intentionally
            // excluded because they are widely used by uptime monitors, CI/CD
            // pipelines, and API clients — blocking them causes false positives.
            $bad_bots = ['ahrefsbot', 'semrushbot', 'mj12bot', 'dotbot', 'petalbot',
                         'baiduspider', 'libwww-perl', 'nmap', 'sqlmap', 'zmeu',
                         'masscan', 'zgrab', 'nikto', 'dirbuster', 'nuclei'];
            foreach ( $bad_bots as $bot ) {
                if ( strpos( $lower_ua, $bot ) !== false ) {
                    $risk_score += 30;
                    $context_signals[] = 'Known Malicious Bot';
                    break;
                }
            }
        }

        // Gather payloads safely
        // Total inspection budget: 256 KB across ALL payloads combined.
        // This prevents memory exhaustion attacks via many large parameters.
        $inspection_budget = 262144; // 256 KB
        $budget_used       = 0;

        $payloads   = [];
        $header_str = $request_uri . $query_string . $user_agent;
        $payloads[] = substr( $header_str, 0, min( strlen( $header_str ), $inspection_budget ) );
        $budget_used += strlen( end( $payloads ) );

        if ( $budget_used < $inspection_budget ) {
            $raw_input = @file_get_contents( 'php://input' );
            if ( $raw_input ) {
                $allowed   = $inspection_budget - $budget_used;
                $chunk     = substr( $raw_input, 0, min( 32768, $allowed ) );
                $payloads[]  = $chunk;
                $budget_used += strlen( $chunk );
            }
        }

        // Add GET/POST/COOKIE parameters under remaining budget
        if ( $budget_used < $inspection_budget ) {
            $input_data = array_merge( $_GET, $_POST, $_COOKIE ); // phpcs:ignore WordPress.Security.NonceVerification
            array_walk_recursive( $input_data, function( $item ) use ( &$payloads, &$budget_used, $inspection_budget ) {
                if ( $budget_used >= $inspection_budget ) return;
                if ( is_string( $item ) && strlen( $item ) > 2 ) {
                    $allowed    = $inspection_budget - $budget_used;
                    $chunk      = substr( $item, 0, min( 16384, $allowed ) );
                    $payloads[] = $chunk;
                    $budget_used += strlen( $chunk );
                }
            });
        }

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
            // SQLi Boolean Tautology — tightened to require numeric/quoted literal
            // on BOTH sides of the = operator AND the classic '1'='1' / 1=1 pattern,
            // which dramatically cuts false-positives from legitimate content like
            // "status=active" or "role=admin" in API payloads.
            'SQLi Boolean Tautology' => ['score' => 40, 'pattern' => '/\b(or|and)\b\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+[\'"]?/i'],
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

        // Admin Content Exemption Context (Gutenberg / Post editing for verified admins).
        //
        // SECURITY: We do NOT fall back to cookie inspection when WordPress has not
        // loaded yet. An attacker can forge any cookie header (the cookie is never
        // cryptographically validated here), so granting WAF exemptions based on an
        // unverified cookie would allow bypassing XSS/SQLi inspection entirely.
        //
        // If WordPress has loaded, we verify via is_user_logged_in() + capability
        // check. Otherwise we apply the full rule-set — a safe default.
        $is_wp_admin_context = false;
        if ( $is_admin_post || $is_gutenberg_api ) {
            if (
                function_exists( 'is_user_logged_in' ) && is_user_logged_in()
                && function_exists( 'current_user_can' ) && current_user_can( 'edit_posts' )
            ) {
                $is_wp_admin_context = true;
            }
            // No cookie fallback — forged cookies would bypass WAF inspection.
        }

        if ( $is_wp_admin_context ) {
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
            // Primary decode: URL-encoded payloads (standard form submissions, GET params).
            $decoded = urldecode( $inspect_string );

            // Secondary decode: HTML/XML entity-encoded payloads.
            // XML-RPC and some XSS vectors hide attack strings inside HTML entities
            // e.g. &#x65;&#x76;&#x61;&#x6c; => eval. urldecode() misses these.
            $decoded = html_entity_decode( $decoded, ENT_QUOTES | ENT_HTML5, 'UTF-8' );

            foreach ( $signal_rules as $signal_name => $rule ) {
                if ( ! isset( $triggered_signals[ $signal_name ] ) && preg_match( $rule['pattern'], $decoded ) ) {
                    $triggered_signals[ $signal_name ] = $rule['score'];
                    $risk_score += $rule['score'];
                }
            }
        }

        // ── Score Floor Rules ─────────────────────────────────────────────────
        // Any single unambiguous attack signal must reach at minimum a SOFT BLOCK
        // (tier 60) regardless of context discounts (e.g. low base score).
        // This prevents a negative context discount from absorbing the penalty.

        // Tier 80 floor: critically dangerous, always hard-block.
        $critical_signals = [
            'Known Vulnerability Exploit', 'PHP Code Execution Payload',
            'Remote File Inclusion',       'Command Injection',
            'SQLi UNION SELECT',
        ];
        foreach ( $critical_signals as $sig ) {
            if ( isset( $triggered_signals[ $sig ] ) ) {
                if ( $risk_score < 80 ) $risk_score = 80;
                break;
            }
        }

        // Tier 60 floor: serious single signals — soft-block at minimum.
        $serious_signals = [
            'Suspicious HTML Script Tag',   'Event Handler Injection',
            'External Script Payload',      'Suspicious JS Protocol',
            'SQLi Boolean Tautology',       'SQLi Functions & Schema',
            'SQLi Comment Injection',       'Path Traversal Probe',
            'Hex/Base64 Obfuscation',
        ];
        foreach ( $serious_signals as $sig ) {
            if ( isset( $triggered_signals[ $sig ] ) ) {
                if ( $risk_score < 60 ) $risk_score = 60;
                break;
            }
        }

        // Tier 60 floor for scanner/attack bots.
        if ( in_array( 'Known Malicious Bot', $context_signals, true ) ) {
            if ( $risk_score < 60 ) $risk_score = 60;
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
            // Do NOT expose the rule name/reason to the attacker.
            echo json_encode( ['error' => 'Access Denied', 'code' => 'forbidden', 'status' => $status_code] );
        } else {
            echo '<!DOCTYPE html><html><head><title>Access Denied</title></head>';
            echo '<body style="font-family:system-ui, sans-serif; text-align:center; padding: 50px; background:#0f172a; color:#fff;">';
            echo '<h1 style="color:#ef4444;">Access Denied</h1>';
            echo '<p>Your request has been blocked by Nexura Security <strong>Endpoint WAF</strong>.</p>';
            // Intentionally omit $reason — do not leak which rule triggered to attacker.
            echo '<p style="font-size: 14px; color: #94a3b8;">Your IP: ' . htmlspecialchars( $ip ) . '</p>';
            echo '</body></html>';
        }
        exit;
    }

    /**
     * Record a strike against an IP and promote to ban when threshold is reached.
     *
     * Uses atomic temp-file + rename to avoid partial writes from concurrent
     * requests. On Windows rename() is not atomic, but the LOCK_EX on the temp
     * write still prevents the most common corruption scenario.
     */
    private function apply_strikes( $ip, $strike_count = 1 ) {
        $strikes_file = NEXURA_WAF_LOG_DIR . '/strikes.json';
        $tmp_file     = $strikes_file . '.tmp.' . getmypid();

        // Read current state.
        $strikes = [];
        if ( file_exists( $strikes_file ) ) {
            $raw = @file_get_contents( $strikes_file );
            if ( $raw !== false ) {
                $strikes = json_decode( $raw, true ) ?: [];
            }
        }

        // Expire entries older than 10 minutes.
        $ten_mins_ago = time() - 600;
        foreach ( $strikes as $s_ip => $data ) {
            if ( ! isset( $data['time'] ) || $data['time'] < $ten_mins_ago ) {
                unset( $strikes[ $s_ip ] );
            }
        }

        if ( ! isset( $strikes[ $ip ] ) ) {
            $strikes[ $ip ] = [ 'count' => 0, 'time' => time() ];
        }
        $strikes[ $ip ]['count'] += $strike_count;
        $strikes[ $ip ]['time']   = time();

        if ( $strikes[ $ip ]['count'] >= 5 ) {
            // Promote to permanent ban.
            $ban_file = NEXURA_WAF_LOG_DIR . '/banned_ips.json';
            $ban_tmp  = $ban_file . '.tmp.' . getmypid();

            $banned_ips = [];
            if ( file_exists( $ban_file ) ) {
                $raw = @file_get_contents( $ban_file );
                if ( $raw !== false ) {
                    $banned_ips = json_decode( $raw, true ) ?: [];
                }
            }
            $banned_ips[ $ip ] = time();

            // Atomic write: write to temp then rename.
            if ( @file_put_contents( $ban_tmp, json_encode( $banned_ips ), LOCK_EX ) !== false ) {
                @rename( $ban_tmp, $ban_file );
            } else {
                @unlink( $ban_tmp );
            }

            // Refresh APCu cache with the updated ban list.
            if ( function_exists( 'apcu_store' ) ) {
                apcu_store( 'nexura_banned_ips', $banned_ips, 3600 );
            }

            unset( $strikes[ $ip ] );
        }

        // Atomic write for strikes file.
        if ( @file_put_contents( $tmp_file, json_encode( $strikes ), LOCK_EX ) !== false ) {
            @rename( $tmp_file, $strikes_file );
        } else {
            @unlink( $tmp_file );
        }
    }

    private function log_attack( $reason, $ip ) {
        // Delegate to WordPress DB Logger if available
        if ( class_exists( '\\Nexura_Security\\Attack_Logger' ) ) {
            \Nexura_Security\Attack_Logger::log_attack( $ip, 'WAF BLOCK: ' . $reason, 'BLOCKED' );
        }

        if ( ! is_dir( NEXURA_WAF_LOG_DIR ) ) {
            @mkdir( NEXURA_WAF_LOG_DIR, 0750, true );

            // --- Protect log directory from direct browser access ---

            // Apache: deny all HTTP access
            $htaccess = NEXURA_WAF_LOG_DIR . '/.htaccess';
            if ( ! file_exists( $htaccess ) ) {
                @file_put_contents(
                    $htaccess,
                    "# Nexura Security — deny direct web access to WAF log files\n"
                    . "<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n"
                    . "<IfModule !mod_authz_core.c>\n    Order deny,allow\n    Deny from all\n</IfModule>\n",
                    LOCK_EX
                );
            }

            // Nginx / any server: a PHP index that returns 403
            $index = NEXURA_WAF_LOG_DIR . '/index.php';
            if ( ! file_exists( $index ) ) {
                @file_put_contents(
                    $index,
                    "<?php http_response_code(403); exit;\n",
                    LOCK_EX
                );
            }
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
            'uri'     => isset( $_SERVER['REQUEST_URI'] )
                ? preg_replace( '/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/', '', $_SERVER['REQUEST_URI'] )
                : 'Unknown'
        ];
        
        @file_put_contents( $file, json_encode( $attacks ), LOCK_EX );
    }

    /**
     * Fixed-window rate limiter.
     *
     * Stores [hits, window_start] so that the 60-second window is anchored to the
     * FIRST request in that window, not reset on every subsequent request (which
     * would create an infinite sliding expiry that never expires for active users).
     */
    private function check_rate_limit( $ip ) {
        if ( ! function_exists( 'apcu_fetch' ) ) {
            return false; // APCu unavailable — skip silently.
        }

        $key  = 'nexura_waf_rate_' . md5( $ip );
        $data = apcu_fetch( $key );
        $now  = time();

        if ( $data === false || ( $now - $data['start'] ) >= $this->rate_limit_window ) {
            // New window: store hit count and window start timestamp.
            apcu_store( $key, [ 'hits' => 1, 'start' => $now ], $this->rate_limit_window + 5 );
            return false;
        }

        $data['hits']++;
        apcu_store( $key, $data, max( 1, $this->rate_limit_window - ( $now - $data['start'] ) + 5 ) );

        return $data['hits'] > $this->rate_limit_hits;
    }

    private function check_geo_block( $ip ) {
        if ( empty( $this->settings['is_pro'] ) ) return false;

        $blocked_file = NEXURA_WAF_LOG_DIR . '/blocked_countries.json';
        if ( ! file_exists( $blocked_file ) ) return false;
        $blocked_countries = json_decode( @file_get_contents( $blocked_file ), true ) ?: [];
        if ( empty( $blocked_countries ) ) return false;

        // HTTP_CF_IPCOUNTRY is only meaningful when the request actually came
        // through Cloudflare. Without this check an attacker can spoof any country
        // code with a custom header and bypass geo-blocking entirely.
        $remote_addr = trim( $_SERVER['REMOTE_ADDR'] ?? '' );
        if ( ! $this->is_cloudflare_ip( $remote_addr ) ) {
            return false; // Not via Cloudflare — country header cannot be trusted.
        }

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

    /**
     * Returns the real visitor IP using only PHP native functions.
     * CF-Connecting-IP is only trusted when the request originates from a
     * known Cloudflare IP range (prevents header-spoofing bypasses).
     * X-Real-IP is only trusted when REMOTE_ADDR is in the configurable
     * trusted_proxies list (falls back to private-IP detection).
     * No WordPress functions are used here — safe for early-bootstrap execution.
     */
    private function get_ip() {
        $remote_addr = trim( $_SERVER['REMOTE_ADDR'] ?? '' );

        // Trust CF-Connecting-IP only when the TCP connection comes from Cloudflare.
        if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && $this->is_cloudflare_ip( $remote_addr ) ) {
            $cf_ip = filter_var( trim( $_SERVER['HTTP_CF_CONNECTING_IP'] ), FILTER_VALIDATE_IP );
            if ( $cf_ip !== false ) {
                return $cf_ip;
            }
        }

        // X-Real-IP: trust only when REMOTE_ADDR is a configured trusted proxy.
        // Falls back to private-IP heuristic when no list is configured.
        if ( ! empty( $_SERVER['HTTP_X_REAL_IP'] ) && $this->is_trusted_proxy( $remote_addr ) ) {
            $real_ip = filter_var( trim( $_SERVER['HTTP_X_REAL_IP'] ), FILTER_VALIDATE_IP );
            if ( $real_ip !== false ) {
                return $real_ip;
            }
        }

        // Fall back to the TCP-level address — always available, never spoofable.
        $ip = filter_var( $remote_addr, FILTER_VALIDATE_IP );
        return ( $ip !== false ) ? $ip : '';
    }

    /**
     * Returns true when $ip is a known trusted reverse proxy.
     *
     * SECURITY: When no trusted_proxies list is configured we do NOT fall back
     * to a private-IP heuristic. A private REMOTE_ADDR does not guarantee the
     * host is a trusted proxy — it could be any machine on the same LAN.
     * Falling back silently would allow any local machine to spoof X-Real-IP.
     *
     * Admins must explicitly set trusted_proxies in waf_settings.json:
     *   { "trusted_proxies": ["127.0.0.1/32", "10.0.0.1/32"] }
     */
    private function is_trusted_proxy( string $ip ): bool {
        $trusted = $this->settings['trusted_proxies'] ?? [];

        if ( empty( $trusted ) || ! is_array( $trusted ) ) {
            return false; // No explicit list — refuse to guess.
        }

        foreach ( $trusted as $cidr ) {
            if ( strpos( $cidr, '/' ) === false ) {
                $cidr .= ( strpos( $cidr, ':' ) !== false ) ? '/128' : '/32';
            }
            if ( $this->ip_in_cidr( $ip, $cidr ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Returns true when $ip falls within a known Cloudflare IPv4/IPv6 CIDR.
     * List source: https://www.cloudflare.com/ips/  (updated 2026-06)
     */
    private function is_cloudflare_ip( string $ip ): bool {
        $cf_ranges = [
            // IPv4
            '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
            '103.31.4.0/22',   '141.101.64.0/18', '108.162.192.0/18',
            '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
            '198.41.128.0/17', '162.158.0.0/15',  '104.16.0.0/13',
            '104.24.0.0/14',   '172.64.0.0/13',   '131.0.72.0/22',
            // IPv6
            '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32',
            '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29',
            '2c0f:f248::/32',
        ];

        foreach ( $cf_ranges as $cidr ) {
            if ( $this->ip_in_cidr( $ip, $cidr ) ) {
                return true;
            }
        }
        return false;
    }

    /** Returns true when $ip is a private or loopback address. */
    private function is_private_ip( string $ip ): bool {
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) === false;
    }

    /** Pure-PHP CIDR membership test — no extensions required. */
    private function ip_in_cidr( string $ip, string $cidr ): bool {
        list( $subnet, $bits ) = explode( '/', $cidr );
        $bits = (int) $bits;

        if ( strpos( $ip, ':' ) !== false ) {
            // IPv6
            $ip_bin     = inet_pton( $ip );
            $subnet_bin = inet_pton( $subnet );
            if ( $ip_bin === false || $subnet_bin === false ) return false;
            $mask = str_repeat( "\xff", (int) ( $bits / 8 ) )
                  . ( $bits % 8 ? chr( 0xff & ( 0xff << ( 8 - $bits % 8 ) ) ) : '' )
                  . str_repeat( "\x00", 16 - (int) ceil( $bits / 8 ) );
            return ( $ip_bin & $mask ) === ( $subnet_bin & $mask );
        }

        // IPv4
        $ip_long     = ip2long( $ip );
        $subnet_long = ip2long( $subnet );
        if ( $ip_long === false || $subnet_long === false ) return false;
        $mask_long = $bits === 0 ? 0 : ( -1 << ( 32 - $bits ) );
        return ( $ip_long & $mask_long ) === ( $subnet_long & $mask_long );
    }
}

if ( ! function_exists( 'nexura_run_endpoint_waf' ) ) {
    function nexura_run_endpoint_waf() {
        try {
            $waf = new NEXURA_Endpoint_WAF();
            $waf->run();
        } catch ( \Throwable $e ) {
            // Fail-open safety: WAF errors must never crash the site.
            // Log to PHP error log so developers can diagnose silent failures.
            // This does NOT expose information to end-users.
            error_log(
                '[Nexura WAF] Unexpected error — WAF skipped. '
                . get_class( $e ) . ': ' . $e->getMessage()
                . ' in ' . $e->getFile() . ':' . $e->getLine()
            );
        }
    }
}
nexura_run_endpoint_waf();
