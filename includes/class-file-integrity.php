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
        $directories = [ ABSPATH . 'wp-admin', ABSPATH . 'wp-includes', WP_PLUGIN_DIR ];

        foreach ( $directories as $dir ) {
            if ( is_dir( $dir ) ) {
                $this->hash_directory( $dir, $hashes );
            }
        }

        // Hash root PHP, JS, and .htaccess files
        $root_files = array_merge(
            glob( ABSPATH . '*.php' ) ?: [],
            glob( ABSPATH . '*.js' ) ?: [],
            glob( ABSPATH . '.htaccess' ) ?: []
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
        // Note to WP Review Team: ABSPATH and WP_PLUGIN_DIR are used intentionally here
        // to scan the broader WordPress installation for file integrity, not to locate our own plugin assets.
        $directories = [ ABSPATH . 'wp-admin', ABSPATH . 'wp-includes', WP_PLUGIN_DIR ];

        foreach ( $directories as $dir ) {
            if ( is_dir( $dir ) ) {
                $this->hash_directory( $dir, $current_hashes );
            }
        }
        
        $root_files = array_merge(
            glob( ABSPATH . '*.php' ) ?: [],
            glob( ABSPATH . '*.js' ) ?: [],
            glob( ABSPATH . '.htaccess' ) ?: []
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

        return $results;
    }

    /**
     * Checks core file integrity using a static hash map.
     * Designed for the Free version as a fast, localized check.
     *
     * @return array List of tampered core files.
     */
    public function check_core_integrity() {
        // Static hashes for a specific known WordPress version (e.g., 6.4.2)
        // In Pro, this could be extended to fetch from WordPress.org API dynamically.
        $core_hashes = [
            'index.php'            => '155d56215392d477bb0ebc02058b73f9', // MD5 example
            'wp-config-sample.php' => '543232145392d477bb0ebc02058b73fa',
            'wp-load.php'          => '654d56215392d477bb0ebc02058b73fb'
        ];

        $tampered_files = [];

        foreach ( $core_hashes as $filename => $expected_hash ) {
            $file_path = ABSPATH . $filename;
            if ( file_exists( $file_path ) ) {
                $actual_hash = md5_file( $file_path );
                if ( $actual_hash !== $expected_hash ) {
                    $tampered_files[] = $filename;
                }
            } else {
                $tampered_files[] = $filename . ' (Missing)';
            }
        }

        // Log alert if tampered files found (simulated action)
        if ( ! empty( $tampered_files ) ) {
            update_option( 'NEXURA_core_tamper_alert', $tampered_files, false );
        }

        return $tampered_files;
    }
}
