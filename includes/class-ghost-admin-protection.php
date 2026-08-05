<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Ghost_Admin_Protection
 * 
 * Detects and mitigates unauthorized administrator accounts created via SQLi or zero-day exploits.
 */
class Ghost_Admin_Protection {

    public function __construct() {
        // Run once daily via a transient check on admin_init, or directly hook to an existing cron
        add_action( 'admin_init', [ $this, 'daily_ghost_admin_scan' ] );
        
        // Also detect immediately if user is registered via normal WP functions
        add_action( 'user_register', [ $this, 'check_new_user_role' ], 10, 1 );
        add_action( 'profile_update', [ $this, 'check_new_user_role' ], 10, 2 );
    }

    /**
     * Checks if a newly registered or updated user is granted admin privileges illegally.
     */
    public function check_new_user_role( $user_id, $old_user_data = null ) {
        if ( ! get_option( 'NEXURA_enable_ghost_admin_protection', '1' ) ) {
            return;
        }

        $user = get_userdata( $user_id );
        if ( ! $user || ! in_array( 'administrator', (array) $user->roles, true ) ) {
            return; // Not an admin
        }

        // If the current user doing the action is NOT an admin themselves (or CLI), it's highly suspicious
        if ( ! is_user_logged_in() || ! current_user_can( 'create_users' ) ) {
            if ( php_sapi_name() !== 'cli' ) {
                // Rogue admin created! Demote immediately.
                $user->set_role( 'subscriber' );
                
                if ( class_exists( '\Nexura_Security\Attack_Logger' ) ) {
                    \Nexura_Security\Attack_Logger::log_attack( 'Localhost/DB', 'Ghost Admin Blocked (' . $user->user_login . ')', 'Demoted to Subscriber' );
                }
            }
        } else {
            // An actual admin created this user, so it's safe. Add to whitelist.
            $known_admins = get_option( 'nexura_known_safe_admins', [] );
            if ( ! in_array( $user_id, $known_admins, true ) ) {
                $known_admins[] = $user_id;
                update_option( 'nexura_known_safe_admins', $known_admins );
            }
        }
    }

    /**
     * Scans for admins created directly via SQL injection (bypassing WP hooks).
     * Runs every 12 hours.
     */
    public function daily_ghost_admin_scan() {
        if ( ! get_option( 'NEXURA_enable_ghost_admin_protection', '1' ) ) {
            return;
        }

        if ( get_transient( 'nexura_ghost_admin_last_scan' ) ) {
            return; // Already scanned recently
        }
        set_transient( 'nexura_ghost_admin_last_scan', time(), 12 * HOUR_IN_SECONDS );

        $known_admins = get_option( 'nexura_known_safe_admins', [] );
        
        $current_admins = get_users( [ 'role' => 'administrator', 'fields' => 'ID' ] );
        
        if ( empty( $known_admins ) ) {
            // First time setup: whitelist all current admins assuming the site is clean right now
            update_option( 'nexura_known_safe_admins', $current_admins );
            return;
        }

        foreach ( $current_admins as $admin_id ) {
            if ( ! in_array( $admin_id, $known_admins, true ) ) {
                // A new admin appeared that we didn't whitelist!
                $user = get_userdata( $admin_id );
                if ( $user ) {
                    $user->set_role( 'subscriber' ); // Demote for safety
                    if ( class_exists( '\Nexura_Security\Attack_Logger' ) ) {
                        \Nexura_Security\Attack_Logger::log_attack( 'Database', 'Ghost Admin DB Scan (' . $user->user_login . ')', 'Demoted to Subscriber' );
                    }
                }
            }
        }
    }
}
