<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}
/**
 * Nexura Security - Auto-Heal (Crash Recovery) Drop-in
 * 
 * This file acts as a WordPress drop-in. When copied to wp-content/fatal-error-handler.php,
 * WordPress will use this instead of its default fatal error handler.
 */

if ( ! class_exists( 'WP_Fatal_Error_Handler' ) ) {
    require_once ABSPATH . WPINC . '/class-wp-fatal-error-handler.php';
}

class Nexura_Fatal_Error_Handler extends WP_Fatal_Error_Handler {

    public function handle() {
        if ( defined( 'WP_SANDBOX_SCRAPING' ) && WP_SANDBOX_SCRAPING ) {
            return;
        }

        if ( function_exists('wp_is_maintenance_mode') && wp_is_maintenance_mode() ) {
            return;
        }

        try {
            $error = $this->detect_error();
            if ( ! $error ) {
                return;
            }

            // Nexura Auto-Heal Logic
            $this->auto_heal( $error );

            // Fallback to default WordPress handling if auto-heal didn't redirect
            if ( ! isset( $GLOBALS['wp_locale'] ) && function_exists( 'load_default_textdomain' ) ) {
                load_default_textdomain();
            }

            $handled = false;
            if ( ! is_multisite() && function_exists('wp_recovery_mode') && wp_recovery_mode()->is_initialized() ) {
                $handled = wp_recovery_mode()->handle_error( $error );
            }

            if ( is_admin() || ! headers_sent() ) {
                $this->display_error_template( $error, $handled );
            }
        } catch ( Exception $e ) {
            // Catch exceptions and remain silent.
        }
    }

    private function auto_heal( $error ) {
        if ( empty( $error['file'] ) ) {
            return;
        }

        $file = wp_normalize_path( $error['file'] );
        // WP_PLUGIN_DIR is always defined when this drop-in runs (WordPress is already loaded).
        $plugin_dir = wp_normalize_path( WP_PLUGIN_DIR );
        // get_theme_root() is the correct WP API — no hardcoded fallback path.
        $theme_dir  = function_exists( 'get_theme_root' ) ? wp_normalize_path( get_theme_root() ) : '';

        // 1. Detect if a Plugin caused the crash
        if ( strpos( $file, $plugin_dir ) === 0 ) {
            $relative_path = str_replace( $plugin_dir . '/', '', $file );
            $parts = explode( '/', $relative_path );
            
            if ( ! empty( $parts ) ) {
                $plugin_folder = $parts[0];
                
                // Do not auto-disable Nexura itself to prevent security loss
                if ( strpos( $plugin_folder, 'nexura-security' ) !== false ) {
                    return;
                }

                // Deactivate the plugin
                $active_plugins = get_option( 'active_plugins', [] );
                if ( ! is_array( $active_plugins ) ) {
                    return;
                }

                $updated = false;
                foreach ( $active_plugins as $index => $plugin ) {
                    if ( strpos( $plugin, $plugin_folder . '/' ) === 0 || $plugin === $plugin_folder . '.php' ) {
                        unset( $active_plugins[ $index ] );
                        $updated = true;
                    }
                }

                if ( $updated ) {
                    $active_plugins = array_values( $active_plugins );
                    update_option( 'active_plugins', $active_plugins );
                    
                    $this->notify_admin( 'Plugin', $plugin_folder, $error );

                    // Reload the page
                    if ( ! headers_sent() ) {
                        header( "Refresh:0" );
                        exit;
                    }
                }
            }
        }

        // 2. Detect if a Theme caused the crash
        if ( strpos( $file, $theme_dir ) === 0 ) {
            $relative_path = str_replace( $theme_dir . '/', '', $file );
            $parts = explode( '/', $relative_path );
            
            if ( ! empty( $parts ) ) {
                $theme_folder = $parts[0];
                $default_theme = defined('WP_DEFAULT_THEME') ? WP_DEFAULT_THEME : 'twentytwentyfour';
                
                if ( $theme_folder !== $default_theme ) {
                    update_option( 'template', $default_theme );
                    update_option( 'stylesheet', $default_theme );

                    $this->notify_admin( 'Theme', $theme_folder, $error );

                    if ( ! headers_sent() ) {
                        header( "Refresh:0" );
                        exit;
                    }
                }
            }
        }
    }

    private function notify_admin( $type, $name, $error ) {
        if ( function_exists( 'wp_mail' ) ) {
            $to      = get_option( 'admin_email' );
            $subject = "[Nexura Auto-Heal] Site Crash Prevented";
            $message = "Hello,\n\n";
            $message .= "Nexura Security's Auto-Heal feature detected a fatal error caused by a {$type} ({$name}) and automatically deactivated it to keep your site online.\n\n";
            $message .= "Error Details:\n";
            $message .= "Message: " . $error['message'] . "\n";
            $message .= "File: " . $error['file'] . " on line " . $error['line'] . "\n\n";
            $message .= "Please investigate the issue with the {$type} before re-activating it.\n";
            
            @wp_mail( $to, $subject, $message );
        }
    }
}

return new Nexura_Fatal_Error_Handler();
