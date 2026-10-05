<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Cron_Persistence_Analyzer
 * 
 * Analyzes WordPress cron jobs for suspicious or hidden tasks
 * that might be recreating malware.
 */
class Cron_Persistence_Analyzer {

    /**
     * Scan WP-Cron array for suspicious jobs.
     * 
     * @return array Array of findings.
     */
    public function analyze_cron() {
        $findings = [];
        $cron_array = _get_cron_array();
        
        if ( ! is_array( $cron_array ) ) {
            return $findings;
        }

        // Core WordPress prefixes
        $core_prefixes = [
            'wp_',
            'recovery_mode_',
            'delete_expired_transients',
        ];

        // Trusted security engine prefixes
        $trusted_prefixes = [
            'nexura_',
            'fs_',
        ];

        // Dynamically discover all active plugin directories and slugs
        $active_plugins = (array) get_option( 'active_plugins', [] );
        if ( is_multisite() ) {
            $sitewide_plugins = (array) get_site_option( 'active_sitewide_plugins', [] );
            $active_plugins = array_merge( $active_plugins, array_keys( $sitewide_plugins ) );
        }

        $active_plugin_slugs = [];
        $active_plugin_dirs  = [];
        $plugin_base_dir     = wp_normalize_path( WP_PLUGIN_DIR );

        foreach ( $active_plugins as $plugin_file ) {
            $dir = dirname( $plugin_file );
            if ( $dir && $dir !== '.' ) {
                $slug = strtolower( $dir );
                $active_plugin_slugs[] = $slug;
                $active_plugin_dirs[]  = $plugin_base_dir . '/' . $slug;
            } else {
                $slug = strtolower( basename( $plugin_file, '.php' ) );
                $active_plugin_slugs[] = $slug;
                $active_plugin_dirs[]  = $plugin_base_dir . '/' . $slug;
            }
        }

        // Active theme directories
        $theme_dirs = [
            wp_normalize_path( get_stylesheet_directory() ),
            wp_normalize_path( get_template_directory() ),
            wp_normalize_path( realpath( get_stylesheet_directory() ) ?: get_stylesheet_directory() ),
            wp_normalize_path( realpath( get_template_directory() ) ?: get_template_directory() ),
        ];

        // Safe base paths (including canonical realpaths for symlinked environments)
        $safe_base_paths = array_unique( [
            $plugin_base_dir,
            wp_normalize_path( realpath( WP_PLUGIN_DIR ) ?: WP_PLUGIN_DIR ),
            wp_normalize_path( ABSPATH . WPINC ),
            wp_normalize_path( realpath( ABSPATH . WPINC ) ?: ( ABSPATH . WPINC ) ),
            wp_normalize_path( ABSPATH . 'wp-admin' ),
            wp_normalize_path( realpath( ABSPATH . 'wp-admin' ) ?: ( ABSPATH . 'wp-admin' ) ),
        ] );

        $upload_dir    = wp_upload_dir();
        $uploads_base  = wp_normalize_path( $upload_dir['basedir'] );
        $uploads_real  = wp_normalize_path( realpath( $upload_dir['basedir'] ) ?: $upload_dir['basedir'] );

        global $wp_filter;
        $processed_hooks = [];

        foreach ( $cron_array as $timestamp => $cronhooks ) {
            foreach ( $cronhooks as $hook => $keys ) {
                if ( isset( $processed_hooks[ $hook ] ) ) {
                    continue;
                }
                $processed_hooks[ $hook ] = true;

                $hook_lower = strtolower( $hook );
                $is_safe    = false;
                $risk_level = 65;
                $evidence   = '';

                // 1. Core prefixes
                foreach ( $core_prefixes as $p ) {
                    if ( strpos( $hook_lower, $p ) === 0 ) {
                        $is_safe = true;
                        break;
                    }
                }

                // 2. Nexura & Freemius prefixes
                if ( ! $is_safe ) {
                    foreach ( $trusted_prefixes as $p ) {
                        if ( strpos( $hook_lower, $p ) === 0 ) {
                            $is_safe = true;
                            break;
                        }
                    }
                }

                // 3. Dynamic Reflection: Inspect registered callbacks in $wp_filter
                if ( ! $is_safe && isset( $wp_filter[ $hook ] ) ) {
                    $wp_hook = $wp_filter[ $hook ];
                    if ( $wp_hook instanceof \WP_Hook ) {
                        foreach ( $wp_hook->callbacks as $priority => $callbacks ) {
                            foreach ( $callbacks as $cb_data ) {
                                $fn = $cb_data['function'];
                                
                                // Detect direct code execution functions
                                if ( is_string( $fn ) && in_array( strtolower( $fn ), [ 'eval', 'assert', 'passthru', 'shell_exec', 'system', 'exec', 'base64_decode' ], true ) ) {
                                    $findings[] = [
                                        'type'     => 'wp_cron',
                                        'hook'     => $hook,
                                        'evidence' => "Critical: WP-Cron hook '{$hook}' executes dangerous function directly: {$fn}()",
                                        'risk'     => 95
                                    ];
                                    $is_safe = true; // Handled as critical finding
                                    break 2;
                                }

                                try {
                                    $file = '';
                                    if ( is_string( $fn ) ) {
                                        if ( strpos( $fn, '::' ) !== false ) {
                                            list( $class, $method ) = explode( '::', $fn, 2 );
                                            if ( class_exists( $class ) && method_exists( $class, $method ) ) {
                                                $ref  = new \ReflectionMethod( $class, $method );
                                                $file = $ref->getFileName();
                                            }
                                        } elseif ( function_exists( $fn ) ) {
                                            $ref  = new \ReflectionFunction( $fn );
                                            $file = $ref->getFileName();
                                        }
                                    } elseif ( is_array( $fn ) && count( $fn ) >= 2 ) {
                                        $class = is_object( $fn[0] ) ? get_class( $fn[0] ) : $fn[0];
                                        $method = $fn[1];
                                        if ( ( class_exists( $class ) || interface_exists( $class ) ) && method_exists( $class, $method ) ) {
                                            $ref  = new \ReflectionMethod( $class, $method );
                                            $file = $ref->getFileName();
                                        }
                                    } elseif ( $fn instanceof \Closure ) {
                                        $ref  = new \ReflectionFunction( $fn );
                                        $file = $ref->getFileName();
                                    } elseif ( is_object( $fn ) && method_exists( $fn, '__invoke' ) ) {
                                        $ref  = new \ReflectionMethod( $fn, '__invoke' );
                                        $file = $ref->getFileName();
                                    }

                                    if ( $file ) {
                                        $norm_file = wp_normalize_path( $file );

                                        // Flag suspicious callback origins (uploads or temporary folders)
                                        if ( strpos( $norm_file, $uploads_base ) !== false || 
                                             strpos( $norm_file, $uploads_real ) !== false || 
                                             strpos( $norm_file, '/wp-content/uploads/' ) !== false || 
                                             strpos( $norm_file, '/tmp/' ) !== false ) {
                                            $findings[] = [
                                                'type'     => 'wp_cron',
                                                'hook'     => $hook,
                                                'evidence' => "Malicious cron callback: '{$hook}' executes script from uploads or temp directory: {$file}",
                                                'risk'     => 95
                                            ];
                                            $is_safe = true;
                                            break 2;
                                        }

                                        // Verify if callback belongs to active plugin or core
                                        foreach ( $safe_base_paths as $safe_path ) {
                                            if ( strpos( $norm_file, $safe_path ) !== false ) {
                                                $is_safe = true;
                                                break 3;
                                            }
                                        }

                                        // Verify if callback belongs to active theme
                                        foreach ( $theme_dirs as $td ) {
                                            if ( strpos( $norm_file, $td ) !== false ) {
                                                $is_safe = true;
                                                break 3;
                                            }
                                        }
                                    }
                                } catch ( \Throwable $e ) {
                                    // Reflection error; proceed to fallback checks
                                }
                            }
                        }
                    }
                }

                // 4. Dynamic active plugin slug matching
                // Allows crons from active plugins where callbacks may only load conditionally
                if ( ! $is_safe ) {
                    foreach ( $active_plugin_slugs as $slug ) {
                        $clean_slug = str_replace( [ '-', '_' ], '', $slug );
                        $clean_hook = str_replace( [ '-', '_' ], '', $hook_lower );

                        if ( strpos( $hook_lower, $slug ) === 0 || strpos( $clean_hook, $clean_slug ) === 0 ) {
                            $is_safe = true;
                            break;
                        }
                    }
                }

                // 5. If not safe, flag as suspicious or orphaned cron persistence
                if ( ! $is_safe ) {
                    $has_callback = isset( $wp_filter[ $hook ] );
                    $evidence_msg = $has_callback 
                        ? "Suspicious WP-Cron hook '{$hook}' detected with unrecognized or non-plugin callback."
                        : "Orphaned WP-Cron hook '{$hook}' detected. Scheduled in database without any active plugin or theme handler.";

                    $findings[] = [
                        'type'     => 'wp_cron',
                        'hook'     => $hook,
                        'evidence' => $evidence_msg,
                        'risk'     => $risk_level
                    ];
                }
            }
        }

        return $findings;
    }
}
