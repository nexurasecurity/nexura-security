<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Reinfection_Engine
 *
 * Core engine for Reinfection Guard. Orchestrates all detectors and
 * analyzers to find the root cause of persistent malware.
 * Uses options-based queue for safe batch processing.
 */
class Reinfection_Engine {

    const STATE_OPTION  = 'NEXURA_reinfection_state';
    const RESULT_OPTION = 'NEXURA_reinfection_result';

    /**
     * Initialize the Reinfection Engine
     */
    public function init() {
        // Future hook-in point (e.g. REST route registration delegation)
    }

    /**
     * Start a new investigation.
     * Resets the state and queues a fresh run.
     *
     * @param string $target_file Specific file to investigate, or empty for full scan.
     */
    public function start_investigation( $target_file = '' ) {
        $state = [
            'status'      => 'running',
            'target_file' => sanitize_text_field( $target_file ),
            'steps'       => [
                'persistence'      => false,
                'file_writer'      => false,  // Step 2: Search PHP source for file writers referencing target
                'cron'             => false,
                'db'               => false,
                'config'           => false,
            ],
            'evidence'    => [],
        ];

        update_option( self::STATE_OPTION, $state, false );
        delete_option( self::RESULT_OPTION );
    }

    /**
     * Process the next pending step.
     * Designed to be called repeatedly by the front-end in a polling loop.
     *
     * @return array Current progress state.
     */
    public function process_step() {
        $state = get_option( self::STATE_OPTION, null );

        if ( ! $state || $state['status'] !== 'running' ) {
            return [ 'done' => true, 'evidence' => [] ];
        }

        // --- Step 1: File-system persistence (MU plugins, drop-ins, uploads PHP) ---
        if ( ! $state['steps']['persistence'] ) {
            if ( class_exists( 'Nexura_Security\Persistence_Detector' ) ) {
                $detector = new Persistence_Detector();
                $state['evidence'] = array_merge( $state['evidence'], $detector->run_checks() );
            }
            $state['steps']['persistence'] = true;
            update_option( self::STATE_OPTION, $state, false );
            return [ 'done' => false, 'step' => 'persistence' ];
        }

        // --- Step 2 & 3: File Writer + Reference Search (target-specific backward investigation) ---
        // Requirements doc: "Search all PHP source for writers" + "Find references to cache.php"
        if ( ! $state['steps']['file_writer'] ) {
            if ( ! empty( $state['target_file'] ) && class_exists( 'Nexura_Security\File_Writer_Analyzer' ) ) {
                $target_basename = basename( $state['target_file'] );
                $evidence = $this->search_references_to_target( $state['target_file'], $target_basename );
                $state['evidence'] = array_merge( $state['evidence'], $evidence );
            }
            $state['steps']['file_writer'] = true;
            update_option( self::STATE_OPTION, $state, false );
            return [ 'done' => false, 'step' => 'file_writer' ];
        }

        // --- Step 4: Cron persistence ---
        if ( ! $state['steps']['cron'] ) {
            if ( class_exists( 'Nexura_Security\Cron_Persistence_Analyzer' ) ) {
                $analyzer = new Cron_Persistence_Analyzer();
                $state['evidence'] = array_merge( $state['evidence'], $analyzer->analyze_cron() );
            }
            $state['steps']['cron'] = true;
            update_option( self::STATE_OPTION, $state, false );
            return [ 'done' => false, 'step' => 'cron' ];
        }

        // --- Step 4: Database persistence (wp_options + MySQL TRIGGERS) ---
        if ( ! $state['steps']['db'] ) {
            if ( class_exists( 'Nexura_Security\DB_Persistence_Analyzer' ) ) {
                $analyzer = new DB_Persistence_Analyzer();
                $state['evidence'] = array_merge( $state['evidence'], $analyzer->analyze_db() );
            }
            $state['steps']['db'] = true;
            update_option( self::STATE_OPTION, $state, false );
            return [ 'done' => false, 'step' => 'db' ];
        }

        // --- Step 5: Config file persistence (.htaccess, .user.ini, wp-config) ---
        if ( ! $state['steps']['config'] ) {
            if ( class_exists( 'Nexura_Security\Config_Persistence_Analyzer' ) ) {
                $analyzer = new Config_Persistence_Analyzer();
                $state['evidence'] = array_merge( $state['evidence'], $analyzer->analyze_configs() );
            }
            $state['steps']['config'] = true;
            update_option( self::STATE_OPTION, $state, false );
            return [ 'done' => false, 'step' => 'config' ];
        }

        // --- All steps done: calculate risk and build report ---
        $evidence = $state['evidence'];

        $risk     = [];
        $graph    = [];
        $report   = [];

        if ( class_exists( 'Nexura_Security\Reinfection_Risk' ) ) {
            $risk_engine = new Reinfection_Risk();
            $risk        = $risk_engine->calculate_risk( $evidence );
        }

        if ( class_exists( 'Nexura_Security\Reinfection_Relationship' ) ) {
            $rel   = new Reinfection_Relationship();
            $graph = $rel->build_relationship( $state['target_file'], $evidence );
        }

        if ( class_exists( 'Nexura_Security\Reinfection_Report' ) ) {
            $reporter = new Reinfection_Report();
            $report   = $reporter->generate_report( $state['target_file'], $evidence, $graph, $risk );
        }

        // Save the final result
        update_option( self::RESULT_OPTION, $report, false );

        // Mark state as done
        $state['status'] = 'done';
        update_option( self::STATE_OPTION, $state, false );

        return [ 'done' => true, 'report' => $report ];
    }

    /**
     * Get the latest investigation result.
     *
     * @return array|false
     */
    public function get_result() {
        return get_option( self::RESULT_OPTION, false );
    }

    /**
     * Search all PHP source files for references to the target file.
     * Implements requirements doc Steps 2 & 3:
     *   - "Search all PHP source for writers"
     *   - "Find references to [target filename]"
     *
     * Searches ABSPATH (excluding uploads) for PHP files containing the
     * target filename or file-writing function calls.
     *
     * @param string $target_path Full path to the target malicious file.
     * @param string $target_name Basename of the target file.
     * @return array Evidence findings.
     */
    private function search_references_to_target( $target_path, $target_name ) {
        $findings   = [];
        $scan_roots = [
            ABSPATH . 'wp-content/plugins/',
            ABSPATH . 'wp-content/themes/',
            WPMU_PLUGIN_DIR,
        ];

        $analyzer = class_exists( 'Nexura_Security\File_Writer_Analyzer' ) ? new File_Writer_Analyzer() : null;

        foreach ( $scan_roots as $root ) {
            if ( ! is_dir( $root ) ) {
                continue;
            }

            try {
                $iterator = new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator( $root, \RecursiveDirectoryIterator::SKIP_DOTS )
                );

                foreach ( $iterator as $file ) {
                    if ( ! $file->isFile() || strtolower( $file->getExtension() ) !== 'php' ) {
                        continue;
                    }

                    // Skip our own plugin files
                    if ( strpos( $file->getPathname(), 'nexura-security' ) !== false ) {
                        continue;
                    }

                    // Size limit: skip files > 500KB to protect CPU
                    if ( $file->getSize() > 524288 ) {
                        continue;
                    }

                    $content = file_get_contents( $file->getPathname() );

                    // Step 3: Does this file reference the target filename?
                    if ( ! empty( $target_name ) && stripos( $content, $target_name ) !== false ) {
                        $findings[] = [
                            'type'     => 'file_reference',
                            'path'     => $file->getPathname(),
                            'evidence' => "File references '{$target_name}' — possible creator or dropper.",
                            'risk'     => 80,
                        ];
                        continue; // Already flagged, no need to check writers too
                    }

                    // Step 2: Does this file contain file-writing capability?
                    if ( $analyzer ) {
                        $analysis = $analyzer->analyze_file( $file->getPathname() );
                        if ( $analysis['is_writer'] || $analysis['is_downloader'] ) {
                            $findings[] = [
                                'type'     => 'file_writer',
                                'path'     => $file->getPathname(),
                                'evidence' => "File can write/download files (uses: " . implode( ', ', $analysis['functions'] ) . ").",
                                'risk'     => 65,
                            ];
                        }
                    }
                }
            } catch ( \Exception $e ) {
                // Permission errors — silently skip
            }
        }

        return $findings;
    }
}

