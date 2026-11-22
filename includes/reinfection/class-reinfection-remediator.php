<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Reinfection_Remediator
 * 
 * Cleans up found persistence mechanisms (Quarantines files, cleans DB/Cron).
 */
class Reinfection_Remediator {

    /**
     * Remediate a specific finding.
     * 
     * @param array $finding The finding data array.
     * @return array Result of the remediation.
     */
    public function remediate( $finding ) {
        if ( ! isset( $finding['type'] ) ) {
            return [ 'success' => false, 'message' => 'Invalid finding format.' ];
        }

        switch ( $finding['type'] ) {
            case 'mu_plugin':
            case 'drop_in':
            case 'uploads_php':
            case 'root_php':
            case 'root_script':    // .py / .js / .sh / .pl scripts in WordPress root
            case 'malware':
            case 'file_reference': // File that references the target
            case 'file_writer':    // File with write/download capabilities
            case 'temp_php':       // PHP in /tmp
            case 'server_log':     // Found in server logs (informational only)
                return $this->quarantine_file( $finding['path'] );

            case 'html_defacement': // Defacement HTML/HTM file in root — direct delete (no quarantine needed)
                return $this->delete_defacement_file( $finding['path'] );

            case 'wp_cron':
                return $this->remove_cron( $finding['hook'] );

            case 'db_payload':
                return $this->remove_db_option( $finding['option'] );

            case 'db_trigger':
                return $this->remove_db_trigger( $finding['option'] ); // 'option' holds trigger name

            case 'config_injection':
            case 'php_fpm_injection':
                return $this->clean_config( $finding['path'] );

            default:
                return [ 'success' => false, 'message' => 'Unknown finding type: ' . sanitize_text_field( $finding['type'] ) ];
        }
    }

    /**
     * Quarantine a file.
     * Also adds .htaccess PHP execution block if the file was in uploads.
     */
    private function quarantine_file( $path ) {
        if ( ! file_exists( $path ) ) {
            return [ 'success' => false, 'message' => 'File not found.' ];
        }

        if ( ! class_exists( '\Nexura_Security\Quarantine' ) ) {
            return [ 'success' => false, 'message' => 'Quarantine module not available.' ];
        }

        $quarantine = new Quarantine();
        $result = $quarantine->quarantine_file( $path );

        if ( $result && ! is_wp_error( $result ) ) {
            // If the file was in the uploads directory, add .htaccess protection
            $upload_dir  = wp_upload_dir();
            $real_parent = realpath( dirname( $path ) );
            $real_upload = realpath( $upload_dir['basedir'] );
            if ( $real_parent && $real_upload && strpos( trailingslashit( wp_normalize_path( $real_parent ) ), trailingslashit( wp_normalize_path( $real_upload ) ) ) === 0 ) {
                $this->protect_uploads_dir( dirname( $path ) );
            }
            return [ 'success' => true, 'message' => 'File successfully quarantined.' ];
        }

        return [ 'success' => false, 'message' => 'Failed to quarantine file.' ];
    }

    /**
     * Write a .htaccess file to block PHP execution in a given directory.
     *
     * @param string $dir Absolute directory path.
     */
    private function protect_uploads_dir( $dir ) {
        $htaccess = trailingslashit( $dir ) . '.htaccess';
        if ( file_exists( $htaccess ) ) return; // Don't overwrite existing

        $rules = "# Nexura Security — Block PHP Execution\n" .
                 "<FilesMatch \"\\.(?:php|phtml|php3|php4|php5|php7|php8)$\">\n" .
                 "    Require all denied\n" .
                 "</FilesMatch>\n";

        file_put_contents( $htaccess, $rules, LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions
    }

    /**
     * Remove a suspicious cron job.
     */
    private function remove_cron( $hook ) {
        if ( empty( $hook ) ) {
            return [ 'success' => false, 'message' => 'Invalid hook name.' ];
        }
        wp_clear_scheduled_hook( $hook );
        return [ 'success' => true, 'message' => "Cron hook '{$hook}' removed." ];
    }

    /**
     * Remove a malicious DB option.
     */
    private function remove_db_option( $option_name ) {
        if ( empty( $option_name ) ) {
            return [ 'success' => false, 'message' => 'Invalid option name.' ];
        }

        // Protect critical WordPress core options from accidental or malicious deletion
        $protected_options = [
            'siteurl', 'home', 'blogname', 'blogdescription', 'users_can_register',
            'admin_email', 'start_of_week', 'use_balanceTags', 'use_smilies', 'require_name_email',
            'comments_notify', 'posts_per_rss', 'rss_use_excerpt', 'mailserver_url', 'mailserver_login',
            'mailserver_pass', 'mailserver_port', 'default_category', 'default_comment_status',
            'default_ping_status', 'default_pingback_flag', 'posts_per_page', 'date_format', 'time_format',
            'links_updated_date_format', 'comment_moderation', 'moderation_notify', 'permalink_structure',
            'rewrite_rules', 'hack_file', 'blog_charset', 'moderation_keys', 'active_plugins',
            'category_base', 'ping_sites', 'comment_max_links', 'gmt_offset', 'default_email_category',
            'recently_edited', 'template', 'stylesheet', 'comment_registration', 'html_type',
            'default_role', 'db_version', 'uploads_use_yearmonth_folders', 'upload_path', 'blog_public',
            'default_link_category', 'show_on_front', 'tag_base', 'show_avatars', 'avatar_rating',
            'upload_url_path', 'thumbnail_size_w', 'thumbnail_size_h', 'thumbnail_crop',
            'medium_size_w', 'medium_size_h', 'avatar_default', 'large_size_w', 'large_size_h',
            'image_default_link_type', 'image_default_size', 'image_default_align', 'close_comments_for_old_posts',
            'close_comments_days_old', 'thread_comments', 'thread_comments_depth', 'page_comments',
            'comments_per_page', 'default_comments_page', 'comment_order', 'sticky_posts', 'widget_categories',
            'widget_text', 'widget_rss', 'uninstall_plugins', 'timezone_string', 'page_for_posts',
            'page_on_front', 'default_post_format', 'cron', 'WPLANG', 'recovery_mode_email_last_sent',
        ];
        global $wpdb;
        $protected_options[] = $wpdb->prefix . 'user_roles';

        if ( in_array( $option_name, $protected_options, true ) ) {
            return [ 'success' => false, 'message' => 'Cannot delete protected WordPress core option.' ];
        }

        delete_option( $option_name );
        return [ 'success' => true, 'message' => "Database option '{$option_name}' removed." ];
    }

    /**
     * Clean config file (basic auto_prepend_file removal).
     */
    private function clean_config( $path ) {
        if ( empty( $path ) || ! file_exists( $path ) ) {
            return [ 'success' => false, 'message' => 'Config file not found.' ];
        }

        // Strict boundary and filename allowlist check
        $real_path    = realpath( $path );
        $real_abspath = realpath( ABSPATH );
        if ( ! $real_path || ! $real_abspath ) {
            return [ 'success' => false, 'message' => 'Invalid config file path.' ];
        }
        $norm_path    = wp_normalize_path( $real_path );
        $norm_abspath = trailingslashit( wp_normalize_path( $real_abspath ) );
        if ( strpos( $norm_path, $norm_abspath ) !== 0 ) {
            return [ 'success' => false, 'message' => 'Config file outside WordPress directory.' ];
        }

        $allowed_basenames = [ '.htaccess', '.user.ini', 'php.ini' ];
        if ( ! in_array( strtolower( basename( $real_path ) ), $allowed_basenames, true ) ) {
            return [ 'success' => false, 'message' => 'Automatic config cleanup is only permitted on .htaccess, .user.ini, or php.ini.' ];
        }

        $content = file_get_contents( $real_path );
        // Remove malicious auto_prepend_file directives while preserving Nexura's own WAF bootstrap
        $clean_content = preg_replace_callback(
            '/^(?:php_value\s+auto_prepend_file\s+[^\r\n]+|auto_prepend_file\s*=\s*[^\r\n]+)$/im',
            function ( $matches ) {
                if ( stripos( $matches[0], 'nexura-waf' ) !== false ) {
                    return $matches[0];
                }
                return '';
            },
            $content
        );

        if ( $content !== $clean_content ) {
            if ( file_put_contents( $real_path, $clean_content ) !== false ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
                return [ 'success' => true, 'message' => 'Config file cleaned.' ];
            }
            return [ 'success' => false, 'message' => 'Failed to write cleaned config.' ];
        }

        return [ 'success' => true, 'message' => 'No known injection matched for automatic removal. Manual review needed.' ];
    }

    /**
     * Drop a malicious MySQL TRIGGER from the database.
     *
     * @param string $trigger_name Name of the DB trigger to remove.
     * @return array
     */
    private function remove_db_trigger( $trigger_name ) {
        if ( empty( $trigger_name ) ) {
            return [ 'success' => false, 'message' => 'Invalid trigger name.' ];
        }

        global $wpdb;

        // Sanitize: only allow alphanumeric and underscore for trigger names
        $safe_name = preg_replace( '/[^a-zA-Z0-9_]/', '', $trigger_name );
        if ( $safe_name !== $trigger_name ) {
            return [ 'success' => false, 'message' => 'Trigger name contains invalid characters.' ];
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $result = $wpdb->query( "DROP TRIGGER IF EXISTS `{$safe_name}`" );

        if ( $result !== false ) {
            return [ 'success' => true, 'message' => "MySQL trigger '{$safe_name}' dropped successfully." ];
        }

        return [ 'success' => false, 'message' => "Failed to drop trigger '{$safe_name}'." ];
    }

    /**
     * Delete an HTML/HTM defacement file from the WordPress root.
     * These files don't require quarantine — they are non-executable defacement pages
     * and can be safely deleted by free users.
     *
     * @param string $path Absolute path to the defacement file.
     * @return array
     */
    private function delete_defacement_file( $path ) {
        if ( empty( $path ) ) {
            return [ 'success' => false, 'message' => 'No file path provided.' ];
        }

        $path = realpath( $path );

        if ( ! $path || ! file_exists( $path ) ) {
            return [ 'success' => false, 'message' => 'Defacement file not found (may have already been deleted).' ];
        }

        // Security: only allow deletion of .html/.htm files in WordPress root
        $abspath = rtrim( realpath( ABSPATH ), '/\\' );
        $file_dir = rtrim( dirname( $path ), '/\\' );

        if ( $file_dir !== $abspath ) {
            return [ 'success' => false, 'message' => 'Security check failed: file is not in WordPress root directory.' ];
        }

        $ext = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
        if ( ! in_array( $ext, [ 'html', 'htm' ], true ) ) {
            return [ 'success' => false, 'message' => 'Security check failed: not an HTML/HTM file.' ];
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
        if ( @unlink( $path ) ) {
            return [ 'success' => true, 'message' => 'Defacement file deleted successfully: ' . basename( $path ) ];
        }

        return [ 'success' => false, 'message' => 'Failed to delete defacement file. Check file permissions.' ];
    }
}


