<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Persistence_Detector
 * 
 * Detects malware persistence mechanisms such as hidden MU plugins,
 * drop-ins, and unauthorized PHP files in uploads or root directory.
 */
class Persistence_Detector {

    /**
     * Run all persistence checks.
     * 
     * @return array Array of detected persistence mechanisms.
     */
    public function run_checks() {
        $findings = [];
        
        $findings = array_merge( $findings, $this->check_mu_plugins() );
        $findings = array_merge( $findings, $this->check_drop_ins() );
        $findings = array_merge( $findings, $this->check_uploads_php() );
        $findings = array_merge( $findings, $this->check_root_php() );
        $findings = array_merge( $findings, $this->check_root_html_defacement() );
        $findings = array_merge( $findings, $this->check_root_scripts() );

        return $findings;
    }

    /**
     * Check MU (Must-Use) Plugins for malicious code.
     * 
     * @return array
     */
    public function check_mu_plugins() {
        $findings = [];
        $mu_dir = WPMU_PLUGIN_DIR;
        
        if ( ! is_dir( $mu_dir ) ) {
            return $findings;
        }

        $files = glob( $mu_dir . '/*.php' );
        if ( ! $files ) return $findings;

        // Known safe host & platform mu-plugins
        $safe_patterns = [
            'kinsta',
            'wpengine',
            'pantheon',
            'godaddy',
            'siteground',
            'bedrock',
        ];

        foreach ( $files as $file ) {
            $basename = strtolower( basename( $file ) );
            $content  = @file_get_contents( $file );

            if ( false === $content ) {
                continue;
            }

            // Check for real malicious signatures (eval, webshells, variable functions)
            $is_malicious = false;
            $malware_reason = '';

            if ( preg_match( '/\b(eval|assert|passthru|shell_exec|system|exec)\s*\(/i', $content ) ) {
                $is_malicious   = true;
                $malware_reason = 'Direct code execution function (eval/system/exec) detected.';
            } elseif ( preg_match( '/base64_decode\s*\(\s*[\'"][A-Za-z0-9+\/=\s]{30,}/i', $content ) ) {
                $is_malicious   = true;
                $malware_reason = 'Obfuscated base64 payload detected.';
            } elseif ( preg_match( '/\$_(POST|GET|REQUEST|COOKIE)\[[^\]]+\]\s*\(/i', $content ) ) {
                $is_malicious   = true;
                $malware_reason = 'Dynamic variable function backdoor detected.';
            }

            if ( $is_malicious ) {
                $findings[] = [
                    'type'     => 'mu_plugin',
                    'path'     => $file,
                    'evidence' => "Malicious MU-Plugin: {$malware_reason}",
                    'risk'     => 90
                ];
                continue;
            }

            // If it's a clean file from a recognized host or has valid plugin headers, do not flag
            $is_known_host = false;
            foreach ( $safe_patterns as $host_slug ) {
                if ( strpos( $basename, $host_slug ) !== false || stripos( $content, $host_slug ) !== false ) {
                    $is_known_host = true;
                    break;
                }
            }

            if ( ! $is_known_host ) {
                // If it doesn't have standard WordPress plugin headers or is an anonymous script
                if ( stripos( $content, 'Plugin Name:' ) === false ) {
                    $findings[] = [
                        'type'     => 'mu_plugin',
                        'path'     => $file,
                        'evidence' => 'Unrecognized anonymous MU Plugin script without plugin headers.',
                        'risk'     => 65
                    ];
                }
            }
        }

        return $findings;
    }

    /**
     * Check Drop-ins (e.g., advanced-cache.php, db.php).
     * 
     * @return array
     */
    public function check_drop_ins() {
        $findings = [];
        $drop_ins = [
            'advanced-cache.php',
            'db.php',
            'db-error.php',
            'install.php',
            'maintenance.php',
            'object-cache.php',
            'fatal-error-handler.php'
        ];

        // Active caching and performance plugin slugs
        $active_plugins = (array) get_option( 'active_plugins', [] );
        $active_str = strtolower( implode( ' ', $active_plugins ) );

        $caching_plugins = [
            'litespeed',
            'wp-rocket',
            'w3-total-cache',
            'wp-super-cache',
            'redis-cache',
            'autoptimize',
            'cache-enabler',
            'hummingbird',
            'sg-cachepress',
            'batcache',
        ];

        $has_active_caching_plugin = false;
        foreach ( $caching_plugins as $cp ) {
            if ( strpos( $active_str, $cp ) !== false ) {
                $has_active_caching_plugin = true;
                break;
            }
        }

        foreach ( $drop_ins as $drop_in ) {
            $file = WP_CONTENT_DIR . '/' . $drop_in;
            if ( file_exists( $file ) ) {
                // Ignore our own drop-in
                if ( $drop_in === 'fatal-error-handler.php' ) {
                    $content = (string) file_get_contents( $file );
                    if ( strpos( $content, 'Nexura Security' ) !== false ) {
                        continue;
                    }
                }

                // If cache drop-in and recognized caching plugin is active, verify clean headers
                if ( in_array( $drop_in, [ 'advanced-cache.php', 'object-cache.php' ], true ) && $has_active_caching_plugin ) {
                    $content = (string) @file_get_contents( $file );
                    // If clean caching code without eval/backdoors, treat as legitimate
                    if ( ! preg_match( '/\b(eval|assert|passthru|shell_exec|system)\s*\(/i', $content ) ) {
                        continue;
                    }
                }

                $findings[] = [
                    'type'     => 'drop_in',
                    'path'     => $file,
                    'evidence' => "Drop-in file '{$drop_in}' present without matching active plugin. Verify legitimacy.",
                    'risk'     => 60
                ];
            }
        }

        return $findings;
    }

    /**
     * Check for any PHP files in the uploads directory (common persistence tactic).
     * 
     * @return array
     */
    public function check_uploads_php() {
        $findings = [];
        $upload_dir = wp_upload_dir();
        $basedir = $upload_dir['basedir'];

        if ( ! is_dir( $basedir ) ) {
            return $findings;
        }

        // Recursive directory iterator to find PHP files in uploads
        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator( $basedir, \RecursiveDirectoryIterator::SKIP_DOTS ),
                \RecursiveIteratorIterator::SELF_FIRST
            );

            $scanned_count = 0;
            $max_scan      = 10000; // Safeguard against execution timeouts on shared hosting

            foreach ( $iterator as $file ) {
                $scanned_count++;
                if ( $scanned_count > $max_scan ) {
                    break;
                }

                // Fast check: Skip non-PHP files immediately
                $filename = $file->getFilename();
                if ( substr( strtolower( $filename ), -4 ) !== '.php' ) {
                    continue;
                }

                if ( $file->isFile() ) {
                    $pathname = wp_normalize_path( $file->getPathname() );
                    $basename = $file->getBasename();

                    // 1. Whitelist all Nexura internal directories (quarantine, backups, logs, cache)
                    if ( strpos( $pathname, '/uploads/nexura-' ) !== false || strpos( $pathname, 'nexura-quarantine' ) !== false ) {
                        continue;
                    }

                    // 2. Whitelist already quarantined Nexura ghost files
                    if ( strpos( $basename, '.NEXURA_ghost_' ) !== false ) {
                        continue;
                    }

                    // 3. Whitelist legitimate directory listing silence files (Silence is golden)
                    if ( $basename === 'index.php' && $file->getSize() <= 150 ) {
                        $content = trim( (string) @file_get_contents( $file->getPathname() ) );
                        if ( stripos( $content, 'Silence is golden' ) !== false || empty( $content ) || $content === '<?php' ) {
                            continue;
                        }
                    }

                    $findings[] = [
                        'type'     => 'uploads_php',
                        'path'     => $file->getPathname(),
                        'evidence' => 'PHP script found in uploads directory.',
                        'risk'     => 90
                    ];
                }
            }
        } catch ( \Throwable $e ) {
            // Gracefully ignore filesystem permission restrictions common on shared hosting
        }

        return $findings;
    }

    /**
     * Check root directory for unknown PHP files.
     * 
     * @return array
     */
    public function check_root_php() {
        $findings = [];
        $root_files = glob( ABSPATH . '*.php' );
        
        if ( ! $root_files ) return $findings;

        // Core WordPress and Nexura Security root files
        $allowed_files = [
            'index.php',
            'wp-activate.php',
            'wp-blog-header.php',
            'wp-comments-post.php',
            'wp-config-sample.php',
            'wp-config.php',
            'wp-cron.php',
            'wp-links-opml.php',
            'wp-load.php',
            'wp-login.php',
            'wp-mail.php',
            'wp-settings.php',
            'wp-signup.php',
            'wp-trackback.php',
            'xmlrpc.php',
            // Nexura Security authorized root scripts & drop-ins
            'nexura-waf.php',
            'nexura-waf-bootstrap.php',
            'nexura-rescue.php',
            'wordfence-waf.php',
        ];

        foreach ( $root_files as $file ) {
            $basename = basename( $file );
            if ( ! in_array( $basename, $allowed_files, true ) ) {
                $findings[] = [
                    'type'     => 'root_php',
                    'path'     => $file,
                    'evidence' => 'Unrecognized PHP file in WordPress root directory.',
                    'risk'     => 80
                ];
            }
        }

        return $findings;
    }

    /**
     * Check root directory for HTML defacement files.
     * Hackers often drop .html or .htm files with defacement messages.
     *
     * @return array
     */
    public function check_root_html_defacement() {
        $findings = [];

        $html_files = array_merge(
            glob( ABSPATH . '*.html' ) ?: [],
            glob( ABSPATH . '*.htm' ) ?: []
        );

        if ( ! $html_files ) {
            return $findings;
        }

        // Common defacement and hacker keywords in content
        $defacement_patterns = [
            'hacked by',
            'defaced by',
            'owned by',
            'greetz:',
            'pwned by',
            'h4ck3d',
            'r00t3d',
            'xss by',
            'shell upload',
            'cyber team',
            'anonymous',
            'exploit by',
        ];

        foreach ( $html_files as $file ) {
            $basename = strtolower( basename( $file ) );

            // Whitelist: skip standard WordPress index pages
            if ( $basename === 'index.html' || $basename === 'index.htm' ) {
                $size = @filesize( $file );
                // A legitimate WordPress index.html is normally tiny (<= 50 bytes)
                if ( $size !== false && $size <= 150 ) {
                    continue;
                }
            }

            $content = strtolower( (string) @file_get_contents( $file ) );

            $is_defacement = false;
            $matched_keyword = '';

            foreach ( $defacement_patterns as $pattern ) {
                if ( strpos( $content, $pattern ) !== false ) {
                    $is_defacement   = true;
                    $matched_keyword = $pattern;
                    break;
                }
            }

            if ( $is_defacement ) {
                $findings[] = [
                    'type'     => 'html_defacement',
                    'path'     => $file,
                    'evidence' => "Defacement HTML file in WordPress root (matched keyword: \"{$matched_keyword}\"). Delete immediately.",
                    'risk'     => 95,
                ];
            } elseif ( 'readme.html' === $basename ) {
                // Stock WordPress readme.html is larger than 5KB and is not a defacement page.
                continue;
            } else {
                // Flag any unknown large HTML at root even without keyword match
                $size = @filesize( $file );
                if ( $size !== false && $size > 5000 ) {
                    $findings[] = [
                        'type'     => 'html_defacement',
                        'path'     => $file,
                        'evidence' => "Unknown HTML file in WordPress root (not part of WordPress core). Review or delete.",
                        'risk'     => 70,
                    ];
                }
            }
        }

        return $findings;
    }

    /**
     * Check WordPress root directory for unknown .py and .js files.
     * Python scripts (.py) and standalone Node/JS scripts (.js) should NEVER
     * exist in a WordPress root — they almost always indicate:
     * - Server-side web shells (Python CGI backdoors)
     * - Malicious Node.js droppers
     * - Cryptocurrency miners
     * - Attacker persistence scripts
     *
     * @return array
     */
    public function check_root_scripts() {
        $findings = [];

        $script_files = array_merge(
            glob( ABSPATH . '*.py' )  ?: [],
            glob( ABSPATH . '*.js' )  ?: [],
            glob( ABSPATH . '*.sh' )  ?: [],
            glob( ABSPATH . '*.pl' )  ?: []
        );

        if ( ! $script_files ) {
            return $findings;
        }

        // Extension-specific risk levels and labels
        $ext_meta = [
            'py' => [ 'risk' => 90, 'label' => 'Python script',     'desc' => 'Python scripts in WordPress root are never legitimate — likely a CGI web shell or dropper.' ],
            'js' => [ 'risk' => 85, 'label' => 'JavaScript script',  'desc' => 'Standalone JS/Node files in WordPress root are not part of WordPress core — likely a Node.js shell or miner.' ],
            'sh' => [ 'risk' => 95, 'label' => 'Shell script',       'desc' => 'Bash/shell scripts in WordPress root are a critical persistence indicator.' ],
            'pl' => [ 'risk' => 90, 'label' => 'Perl script',        'desc' => 'Perl scripts are commonly used as backdoors and CGI web shells.' ],
        ];

        foreach ( $script_files as $file ) {
            $ext  = strtolower( pathinfo( $file, PATHINFO_EXTENSION ) );
            $meta = isset( $ext_meta[ $ext ] ) ? $ext_meta[ $ext ] : [ 'risk' => 80, 'label' => ucfirst( $ext ) . ' script', 'desc' => 'Unrecognized script file in WordPress root.' ];

            $findings[] = [
                'type'     => 'root_script',
                'path'     => $file,
                'evidence' => $meta['label'] . ' found in WordPress root: ' . basename( $file ) . '. ' . $meta['desc'],
                'risk'     => $meta['risk'],
            ];
        }

        return $findings;
    }
}
