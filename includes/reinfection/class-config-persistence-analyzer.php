<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Config_Persistence_Analyzer
 * 
 * Checks core config files (.htaccess, .user.ini, wp-config.php)
 * for auto_prepend_file or unauthorized includes.
 */
class Config_Persistence_Analyzer {

    /**
     * Scan configuration files.
     * 
     * @return array Array of findings.
     */
    public function analyze_configs() {
        $findings = [];
        
        $files_to_check = [
            '.htaccess'       => ABSPATH . '.htaccess',
            '.user.ini'       => ABSPATH . '.user.ini',
            'php.ini'         => ABSPATH . 'php.ini',
            'wp-config.php'   => ABSPATH . 'wp-config.php'
        ];

        foreach ( $files_to_check as $name => $path ) {
            if ( file_exists( $path ) ) {
                $content = file_get_contents( $path );
                if ( ! is_string( $content ) ) {
                    continue;
                }

                // Check for auto_prepend_file
                if ( stripos( $content, 'auto_prepend_file' ) !== false ) {
                    // Whitelist Nexura's own auto_prepend_file
                    if ( stripos( $content, 'nexura-waf-bootstrap.php' ) === false ) {
                        $findings[] = [
                            'type'     => 'config_injection',
                            'path'     => $path,
                            'evidence' => "auto_prepend_file detected in {$name}",
                            'risk'     => 95
                        ];
                    }
                }

                // wp-config.php always loads wp-settings.php. Only other includes are suspicious.
                if ( $name === 'wp-config.php' ) {
                    $suspicious_includes = $this->find_unauthorized_includes( $content );
                    if ( ! empty( $suspicious_includes ) ) {
                        $findings[] = [
                            'type'     => 'config_injection',
                            'path'     => $path,
                            'evidence' => 'Suspicious include/require found in wp-config.php: ' . implode( ' | ', $suspicious_includes ),
                            'risk'     => 95
                        ];
                    }
                }
            }
        }

        return $findings;
    }

    /**
     * Include/require lines in wp-config.php that are not the core wp-settings.php bootstrap.
     *
     * @param string $content File contents.
     * @return string[]
     */
    private function find_unauthorized_includes( $content ) {
        $code = $this->strip_php_comments( $content );
        if ( ! preg_match_all(
            '/\b(?:include|require)(?:_once)?\b\s*(?:\((?:[^()]|\([^()]*\))*\)|[^;{]+)\s*;/i',
            $code,
            $matches
        ) ) {
            return [];
        }

        $suspicious = [];
        foreach ( $matches[0] as $statement ) {
            $statement = trim( preg_replace( '/\s+/', ' ', $statement ) );
            if ( $this->is_core_wp_settings_include( $statement ) ) {
                continue;
            }
            $suspicious[] = $statement;
        }

        return $suspicious;
    }

    /**
     * WordPress core ends wp-config.php by loading wp-settings.php.
     *
     * @param string $statement Include or require statement.
     * @return bool
     */
    private function is_core_wp_settings_include( $statement ) {
        $normalized = preg_replace( '/\s+/', '', $statement );

        return (bool) preg_match(
            '/^(?:include|require)(?:_once)?(?:\()?(?:ABSPATH|__DIR__|dirname\(__FILE__\))(?:\.DIRECTORY_SEPARATOR)?\.[\'"]\/?wp-settings\.php[\'"]\)?;$/i',
            $normalized
        );
    }

    /**
     * Drop comments so documentation text is not scanned as code.
     *
     * @param string $content File contents.
     * @return string
     */
    private function strip_php_comments( $content ) {
        $stripped = preg_replace( '/\/\*.*?\*\//s', '', $content );
        $stripped = preg_replace( '/^\s*\/\/.*$/m', '', $stripped );
        $stripped = preg_replace( '/^\s*#.*$/m', '', $stripped );

        return is_string( $stripped ) ? $stripped : $content;
    }
}
