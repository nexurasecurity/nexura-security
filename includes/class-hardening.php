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



        // API Hardening
        if ( get_option( 'NEXURA_disable_xmlrpc', '0' ) === '1' ) {
            add_filter( 'xmlrpc_enabled', '__return_false' );
        }
        add_filter( 'rest_authentication_errors', [ $this, 'restrict_rest_api' ] );
    }

    /**
     * Restricts the REST API to authenticated users to prevent enumeration.
     */
    public function restrict_rest_api( $result ) {
        if ( ! empty( $result ) ) {
            return $result;
        }
        
        // Only restrict if the setting is explicitly enabled
        if ( ! get_option( 'NEXURA_restrict_rest_api', false ) ) {
            return $result;
        }

        if ( ! is_user_logged_in() ) {
            return new \WP_Error(
                'rest_not_logged_in',
                __( 'Nexura: REST API restricted to authenticated users.', 'nexura-security' ),
                [ 'status' => 401 ]
            );
        }
        return $result;
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
        return (bool) get_option( $rule_key, false );
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
            'Options -Indexes',
            '<Files *.php>',
            'Require all denied',
            '</Files>'
        ];
        
        require_once ABSPATH . 'wp-admin/includes/misc.php';
        insert_with_markers( $htaccess_file, 'Nexura Security Uploads', $rules );
    }

    private function unprotect_uploads_directory() {
        $upload_dir = wp_upload_dir();
        $htaccess_file = $upload_dir['basedir'] . '/.htaccess';
        
        require_once ABSPATH . 'wp-admin/includes/misc.php';
        insert_with_markers( $htaccess_file, 'Nexura Security Uploads', [] );
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
            $rules[] = 'Require all denied';
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
            $rules[] = '<IfModule mod_rewrite.c>';
            $rules[] = 'RewriteEngine On';
            $rules[] = 'RewriteCond %{HTTPS} off';
            $rules[] = 'RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]';
            $rules[] = '</IfModule>';
        }

        // 8. WAF & Auto-Restore (auto_prepend_file)
        if ( $this->is_rule_enabled( 'NEXURA_enable_waf' ) ) {
            $waf_path = NEXURA_PLUGIN_DIR . 'nexura-waf.php';
            $rules[] = '<IfModule mod_php.c>';
            $rules[] = 'php_value auto_prepend_file "' . $waf_path . '"';
            $rules[] = '</IfModule>';
            $rules[] = '<IfModule php_module>';
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
        
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable
        if ( file_exists( $htaccess_file ) && ! is_writable( $htaccess_file ) ) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
            @chmod( $htaccess_file, 0644 );
        }
        
        insert_with_markers( $htaccess_file, 'Nexura Security', $rules );
        
        // Write to .user.ini for CGI/FastCGI/Litespeed servers (cPanel, Nginx, etc.)
        $user_ini_file = get_home_path() . '.user.ini';
        $ini_marker_start = "; BEGIN Nexura Security\n";
        $ini_marker_end   = "; END Nexura Security\n";
        
        $current_ini = file_exists( $user_ini_file ) ? @file_get_contents( $user_ini_file ) : '';
        // Remove old Nexura block
        $pattern = '/; BEGIN Nexura Security.*?; END Nexura Security\n?/s';
        $current_ini = preg_replace( $pattern, '', $current_ini );
        
        if ( $this->is_rule_enabled( 'NEXURA_enable_waf' ) ) {
            $new_ini = $ini_marker_start . "auto_prepend_file = '{$waf_path}'\n" . $ini_marker_end;
            $current_ini = trim( $current_ini ) . "\n\n" . $new_ini;
        }
        
        if ( ! empty( trim( $current_ini ) ) ) {
            @file_put_contents( $user_ini_file, trim( $current_ini ) . "\n" );
        } elseif ( file_exists( $user_ini_file ) ) {
            wp_delete_file( $user_ini_file );
        }

        if ( get_option( 'nexura_server_lock_applied' ) && file_exists( $htaccess_file ) ) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
            @chmod( $htaccess_file, 0444 );
        }
    }
}
