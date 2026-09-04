<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Hardening
 * 
 * Applies security tweaks (disabling editors, headers, etc.).
 */
class Hardening {

    /**
     * Safely updates .htaccess and rolls back if it causes a 500 error.
     */
    public static function safe_htaccess_update( $file, $marker, $rules ) {
        require_once ABSPATH . 'wp-admin/includes/misc.php';
        
        $original_content = file_exists( $file ) ? @file_get_contents( $file ) : '';
        
        $result = insert_with_markers( $file, $marker, $rules );
        
        if ( $result ) {
            // Test if site is still accessible
            $test_url = home_url();
            $response = wp_remote_get( $test_url, [
                'timeout'   => 5,
                'sslverify' => false,
            ] );
            
            // If response is HTTP 500+ (meaning actual server crash)
            if ( ! is_wp_error( $response ) && wp_remote_retrieve_response_code( $response ) >= 500 ) {
                // Rollback
                if ( $original_content !== false && $original_content !== '' ) {
                    @file_put_contents( $file, $original_content );
                } else {
                    // File didn't exist or was empty
                    @file_put_contents( $file, '' );
                }
                return false;
            }
        }
        return $result;
    }

    /**
     * Applies enabled security hardening rules.
     */
    public function apply_rules() {
        // Disable file editor (Available in Free)
        if ( $this->is_rule_enabled( 'NEXURA_disable_file_editor' ) ) {
            if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
                define( 'DISALLOW_FILE_EDIT', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound
            }
            add_filter( 'map_meta_cap', [ $this, 'NEXURA_disable_file_editor_caps' ], 10, 2 );
        }



        // API Hardening (Now handled by REST_Security_Free class)
    }


    /**
     * Disables the file editor capabilities.
     */
    public function NEXURA_disable_file_editor_caps( $caps, $cap ) {
        if ( in_array( $cap, [ 'edit_themes', 'edit_plugins', 'edit_files' ] ) ) {
            $caps = [ 'do_not_allow' ];
        }
        return $caps;
    }

    /**
     * Checks if a specific hardening rule is enabled in settings.
     *
     * @param string $rule_key The key for the hardening rule.
     * @return bool
     */
    private function is_rule_enabled( $rule_key ) {
        $val = get_option( $rule_key, false );
        if ( $val === 'disabled' ) {
            return false;
        }
        return (bool) $val;
    }


    /**
     * Initializes hooks for .htaccess rules rebuilding.
     */
    public function init_hooks() {
        $options = [
            'NEXURA_htaccess_wpconfig',
            'NEXURA_htaccess_indexes',
            'NEXURA_htaccess_file',
            'NEXURA_htaccess_xmlrpc',
            'NEXURA_htaccess_signature',
            'NEXURA_htaccess_author',
            'NEXURA_force_ssl',
            'NEXURA_enable_waf'
        ];

        foreach ( $options as $opt ) {
            add_action( "update_option_{$opt}", [ $this, 'rebuild_htaccess_rules' ], 10, 0 );
            add_action( "add_option_{$opt}", [ $this, 'rebuild_htaccess_rules' ], 10, 0 );
            add_action( "delete_option_{$opt}", [ $this, 'rebuild_htaccess_rules' ], 10, 0 );
        }

        add_action( "update_option_block_php_uploads", [ $this, 'toggle_uploads_protection' ], 10, 0 );
        add_action( "add_option_block_php_uploads", [ $this, 'toggle_uploads_protection' ], 10, 0 );
        add_action( "delete_option_block_php_uploads", [ $this, 'toggle_uploads_protection' ], 10, 0 );
    }

    /**
     * Toggles the uploads directory .htaccess protection.
     */
    public function toggle_uploads_protection() {
        if ( $this->is_rule_enabled( 'block_php_uploads' ) ) {
            $this->protect_uploads_directory();
        } else {
            $this->unprotect_uploads_directory();
        }
    }

    private function protect_uploads_directory() {
        $upload_dir = wp_upload_dir();
        $htaccess_file = $upload_dir['basedir'] . '/.htaccess';
        
        $rules = [
            '<IfModule mod_autoindex.c>',
            'Options -Indexes',
            '</IfModule>',
            '<Files *.php>',
            '<IfModule mod_authz_core.c>',
            'Require all denied',
            '</IfModule>',
            '<IfModule !mod_authz_core.c>',
            'Order allow,deny',
            'Deny from all',
            '</IfModule>',
            '</Files>'
        ];
        
        require_once ABSPATH . 'wp-admin/includes/misc.php';
        self::safe_htaccess_update( $htaccess_file, 'Nexura Security Uploads', $rules );
    }

    private function unprotect_uploads_directory() {
        $upload_dir = wp_upload_dir();
        $htaccess_file = $upload_dir['basedir'] . '/.htaccess';
        
        require_once ABSPATH . 'wp-admin/includes/misc.php';
        self::safe_htaccess_update( $htaccess_file, 'Nexura Security Uploads', [] );
    }

    /**
     * Rebuilds the .htaccess file with active security rules.
     */
    public function rebuild_htaccess_rules() {
        require_once ABSPATH . 'wp-admin/includes/misc.php';

        $htaccess_file = get_home_path() . '.htaccess';
        $rules = [];

        // 3. Protect .htaccess itself
        if ( $this->is_rule_enabled( 'NEXURA_htaccess_file' ) ) {
            $rules[] = '<Files .htaccess>';
            $rules[] = 'Require all denied';
            $rules[] = '</Files>';
        }

        // 4. Disable XML-RPC
        if ( $this->is_rule_enabled( 'NEXURA_htaccess_xmlrpc' ) ) {
            $rules[] = '<Files xmlrpc.php>';
            $rules[] = '<IfModule mod_authz_core.c>';
            $rules[] = 'Require all denied';
            $rules[] = '</IfModule>';
            $rules[] = '<IfModule !mod_authz_core.c>';
            $rules[] = 'Order allow,deny';
            $rules[] = 'Deny from all';
            $rules[] = '</IfModule>';
            $rules[] = '</Files>';
        }

        // 5. Disable Server Signature
        if ( $this->is_rule_enabled( 'NEXURA_htaccess_signature' ) ) {
            $rules[] = 'ServerSignature Off';
        }

        // 6. Block Author Scans
        if ( $this->is_rule_enabled( 'NEXURA_htaccess_author' ) ) {
            $rules[] = '<IfModule mod_rewrite.c>';
            $rules[] = 'RewriteEngine On';
            $rules[] = 'RewriteCond %{QUERY_STRING} (author=\d+) [NC]';
            $rules[] = 'RewriteRule .* - [F]';
            $rules[] = '</IfModule>';
        }

        // 7. Force SSL (HTTPS)
        if ( $this->is_rule_enabled( 'NEXURA_force_ssl' ) ) {
            // Extract canonical host from WordPress home URL to prevent HTTP_HOST injection attacks.
            $canonical_host = wp_parse_url( home_url(), PHP_URL_HOST );
            
            if ( $canonical_host ) {
                // Escape dots for Apache regex (not preg_quote which uses PHP regex delimiters)
                $escaped_host = str_replace( '.', '\.', $canonical_host );
                
                // Block #1 (separate IfModule): Reject requests with non-canonical Host header
                $rules[] = '<IfModule mod_rewrite.c>';
                $rules[] = 'RewriteEngine On';
                $rules[] = 'RewriteCond %{HTTP_HOST} !^(www\.)?' . $escaped_host . '$ [NC]';
                $rules[] = 'RewriteRule .* - [F,L]';
                $rules[] = '</IfModule>';
                
                // Block #2 (separate IfModule): Force HTTPS using hardcoded canonical host
                // Must be a separate block — [F,L] in Block #1 would short-circuit rules in same block
                $rules[] = '<IfModule mod_rewrite.c>';
                $rules[] = 'RewriteEngine On';
                $rules[] = 'RewriteCond %{HTTPS} off';
                $rules[] = 'RewriteRule ^(.*)$ https://' . $canonical_host . '%{REQUEST_URI} [L,R=301]';
                $rules[] = '</IfModule>';
            }
        }

        // 8. WAF & Auto-Restore (auto_prepend_file)
        // $waf_path declared here (outside if) so .user.ini block below can access it too
        $waf_path = NEXURA_PLUGIN_DIR . 'nexura-waf.php';
        $is_apache_mod = ( strpos( php_sapi_name(), 'apache' ) !== false );
        if ( $this->is_rule_enabled( 'NEXURA_enable_waf' ) && file_exists( $waf_path ) && $is_apache_mod ) {
            $rules[] = '<IfModule mod_php.c>';
            $rules[] = 'php_value auto_prepend_file "' . $waf_path . '"';
            $rules[] = '</IfModule>';
            $rules[] = '<IfModule mod_php7.c>';
            $rules[] = 'php_value auto_prepend_file "' . $waf_path . '"';
            $rules[] = '</IfModule>';
            $rules[] = '<IfModule mod_php8.c>';
            $rules[] = 'php_value auto_prepend_file "' . $waf_path . '"';
            $rules[] = '</IfModule>';
        }

        // Write to file using WordPress native function
        $rules = apply_filters( 'nexura_htaccess_rules', $rules );
        
        // Ensure .htaccess is writable before writing
        if ( file_exists( $htaccess_file ) ) {
            @chmod( $htaccess_file, 0644 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
            
            // Clean up any legacy nexura-security-pro path in existing .htaccess
            $current_htaccess = @file_get_contents( $htaccess_file );
            if ( $current_htaccess && strpos( $current_htaccess, 'nexura-security-pro' ) !== false ) {
                $cleaned_htaccess = str_replace( 'nexura-security-pro', basename( NEXURA_PLUGIN_DIR ), $current_htaccess );
                @file_put_contents( $htaccess_file, $cleaned_htaccess );
            }
        }
        
        self::safe_htaccess_update( $htaccess_file, 'Nexura Security', $rules );
        
        // Write to .user.ini for CGI/FastCGI/Litespeed servers (cPanel, Nginx, etc.)
        $user_ini_file = get_home_path() . '.user.ini';
        $ini_marker_start = "; BEGIN Nexura Security\n";
        $ini_marker_end   = "; END Nexura Security\n";
        
        $current_ini = file_exists( $user_ini_file ) ? @file_get_contents( $user_ini_file ) : '';
        // Remove old Nexura block and legacy nexura-security-pro path
        $pattern = '/; BEGIN Nexura Security.*?; END Nexura Security\n?/s';
        $current_ini = preg_replace( $pattern, '', (string) $current_ini );
        if ( strpos( $current_ini, 'nexura-security-pro' ) !== false ) {
            $current_ini = str_replace( 'nexura-security-pro', basename( NEXURA_PLUGIN_DIR ), $current_ini );
        }
        
        if ( $this->is_rule_enabled( 'NEXURA_enable_waf' ) && file_exists( $waf_path ) ) {
            $new_ini = $ini_marker_start . "auto_prepend_file = '{$waf_path}'\n" . $ini_marker_end;
            $current_ini = trim( $current_ini ) . "\n\n" . $new_ini;
        }
        
        if ( ! empty( trim( $current_ini ) ) ) {
            @file_put_contents( $user_ini_file, trim( $current_ini ) . "\n" );
        } elseif ( file_exists( $user_ini_file ) ) {
            wp_delete_file( $user_ini_file );
        }

        if ( get_option( 'nexura_server_lock_applied' ) && file_exists( $htaccess_file ) ) {
            @chmod( $htaccess_file, 0444 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
        }
    }
}
