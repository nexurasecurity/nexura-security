<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class File_Integrity
 * 
 * Handles baseline hashing and File Integrity Monitoring (FIM).
 */
class File_Integrity {

    private $baseline_file;

    public function __construct() {
        $upload_dir = wp_upload_dir();
        $this->baseline_file = trailingslashit( $upload_dir['basedir'] ) . 'nexura-logs/fim-baseline.json';
        $this->ensure_dir();
    }

    private function ensure_dir() {
        $dir = dirname( $this->baseline_file );
        if ( ! file_exists( $dir ) ) {
            wp_mkdir_p( $dir );
            file_put_contents( $dir . '/.htaccess', "Deny from all\n" );
            file_put_contents( $dir . '/index.php', "<?php\n// Silence is golden.\n" );
        }
    }

    /**
     * Generates a baseline of file hashes.
     *
     * @return array Result message.
     */
    public function generate_baseline() {
        $hashes = [];
        $directories = [ 
            ABSPATH . 'wp-admin', 
            ABSPATH . 'wp-includes', 
            WP_PLUGIN_DIR,
            get_theme_root(),
            defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins'
        ];

        foreach ( $directories as $dir ) {
            if ( is_dir( $dir ) ) {
                $this->hash_directory( $dir, $hashes );
            }
        }

        // Hash root PHP, JS, and .htaccess files
        $root_files = array_merge(
            glob( ABSPATH . '*.php' ) ?: [],
            glob( ABSPATH . '*.js' ) ?: [],
            glob( ABSPATH . '.htaccess' ) ?: [],
            // Drop-ins like advanced-cache.php, object-cache.php, db.php
            glob( WP_CONTENT_DIR . '/*.php' ) ?: []
        );
        if ( is_array( $root_files ) ) {
            foreach ( $root_files as $file ) {
                if ( is_file( $file ) ) {
                    $hashes[ $file ] = hash_file( 'sha256', $file );
                }
            }
        }

        $result = file_put_contents( $this->baseline_file, json_encode( $hashes ) );
        
        return [
            'success' => $result !== false,
            'message' => $result !== false ? 'Baseline generated with ' . count($hashes) . ' files.' : 'Failed to save baseline.'
        ];
    }

    /**
     * Recursively hashes files in a directory.
     */
    private function hash_directory( $dir, &$hashes ) {
        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS )
            );

            foreach ( $iterator as $file ) {
                if ( $file->isFile() ) {
                    $ext = strtolower( $file->getExtension() );
                    $name = $file->getFilename();
                    if ( $ext === 'php' || $ext === 'js' || $name === '.htaccess' ) {
                        $hashes[ $file->getPathname() ] = hash_file( 'sha256', $file->getPathname() );
                    }
                }
            }
        } catch ( \Exception $e ) {
            // Ignore unreadable dirs
        }
    }

    /**
     * Compares current files against the baseline.
     *
     * @return array List of added, modified, or deleted files.
     */
    public function check_integrity() {
        if ( ! file_exists( $this->baseline_file ) ) {
            return [ 'error' => 'No baseline found. Please generate one first.' ];
        }

        $baseline = json_decode( file_get_contents( $this->baseline_file ), true );
        if ( ! is_array( $baseline ) ) {
            return [ 'error' => 'Baseline data is corrupt.' ];
        }

        $current_hashes = [];
        $directories = [ 
            ABSPATH . 'wp-admin', 
            ABSPATH . 'wp-includes', 
            WP_PLUGIN_DIR,
            get_theme_root(),
            defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins'
        ];

        foreach ( $directories as $dir ) {
            if ( is_dir( $dir ) ) {
                $this->hash_directory( $dir, $current_hashes );
            }
        }
        
        $root_files = array_merge(
            glob( ABSPATH . '*.php' ) ?: [],
            glob( ABSPATH . '*.js' ) ?: [],
            glob( ABSPATH . '.htaccess' ) ?: [],
            // Drop-ins like advanced-cache.php, object-cache.php, db.php
            glob( WP_CONTENT_DIR . '/*.php' ) ?: []
        );
        if ( is_array( $root_files ) ) {
            foreach ( $root_files as $file ) {
                if ( is_file( $file ) ) {
                    $current_hashes[ $file ] = hash_file( 'sha256', $file );
                }
            }
        }

        $results = [
            'added'    => [],
            'modified' => [],
            'deleted'  => []
        ];

        // Check for modified and deleted
        foreach ( $baseline as $file => $hash ) {
            if ( ! isset( $current_hashes[ $file ] ) ) {
                $results['deleted'][] = $file;
            } elseif ( $current_hashes[ $file ] !== $hash ) {
                $results['modified'][] = $file;
            }
        }

        // Check for added
        foreach ( $current_hashes as $file => $hash ) {
            if ( ! isset( $baseline[ $file ] ) ) {
                $results['added'][] = $file;
            }
        }

        // Save history if there are changes
        if ( ! empty( $results['added'] ) || ! empty( $results['modified'] ) || ! empty( $results['deleted'] ) ) {
            $history = get_option( 'NEXURA_fim_history', [] );
            if ( ! is_array( $history ) ) {
                $history = [];
            }
            array_unshift( $history, [
                'time'     => current_time( 'mysql' ),
                'added'    => count( $results['added'] ),
                'modified' => count( $results['modified'] ),
                'deleted'  => count( $results['deleted'] )
            ] );
            
            // Keep only the last 50 entries
            if ( count( $history ) > 50 ) {
                $history = array_slice( $history, 0, 50 );
            }
            update_option( 'NEXURA_fim_history', $history );
        }

        return $results;
    }

    /**
     * Checks core file integrity using a static hash map.
     * Designed for the Free version as a fast, localized check.
     *
     * @return array List of tampered core files.
     */
    public function check_core_integrity() {
        global $wp_version;
        if ( ! function_exists( 'get_core_checksums' ) ) {
            require_once ABSPATH . 'wp-admin/includes/update.php';
        }

        $checksums = function_exists( 'get_core_checksums' ) ? get_core_checksums( $wp_version, get_locale() ) : false;
        if ( ! is_array( $checksums ) || empty( $checksums ) ) {
            return [];
        }

        $core_files = [ 'index.php', 'wp-load.php', 'wp-settings.php', 'wp-login.php' ];
        $tampered_files = [];

        foreach ( $core_files as $filename ) {
            if ( ! isset( $checksums[ $filename ] ) ) {
                continue;
            }
            $file_path = ABSPATH . $filename;
            if ( file_exists( $file_path ) ) {
                $actual_hash = md5_file( $file_path );
                if ( $actual_hash !== $checksums[ $filename ] ) {
                    $tampered_files[] = $filename;
                }
            } else {
                $tampered_files[] = $filename . ' (Missing)';
            }
        }

        if ( ! empty( $tampered_files ) ) {
            update_option( 'NEXURA_core_tamper_alert', $tampered_files, false );
        } else {
            delete_option( 'NEXURA_core_tamper_alert' );
        }

        return $tampered_files;
    }
}
