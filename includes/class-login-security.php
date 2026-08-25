<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Login_Security
 * 
 * Handles global 2FA enforcement by role and grace period logic.
 */
class Login_Security {

    public function init() {
        add_action( 'wp_login', [ $this, 'enforce_2fa_policy' ], 5, 2 );
        add_action( 'wp_login', [ $this, 'record_last_login' ], 10, 2 );
        add_action( 'admin_init', [ $this, 'check_grace_period_enforcement' ] );
        add_action( 'admin_init', [ $this, 'update_db_schema' ] );
        add_action( 'admin_init', [ $this, 'cleanup_recaptcha_logs' ] );

        // Add Last Login column if enabled
        if ( get_option( 'NEXURA_show_last_login', '1' ) === '1' ) {
            add_filter( 'manage_users_columns', [ $this, 'add_last_login_column' ] );
            add_filter( 'manage_users_custom_column', [ $this, 'populate_last_login_column' ], 10, 3 );
        }
    }

    /**
     * Ensures the database schema is up to date (specifically for reCAPTCHA logs).
     */
    public function update_db_schema() {
        if ( get_option( 'NEXURA_recaptcha_db_version' ) !== '1.0' ) {
            \Nexura_Security\Activator::activate();
            update_option( 'NEXURA_recaptcha_db_version', '1.0' );
        }
    }

    /**
     * Cleans up reCAPTCHA logs older than 30 days.
     */
    public function cleanup_recaptcha_logs() {
        $last_cleanup = get_option( 'NEXURA_recaptcha_last_cleanup', 0 );
        if ( time() - $last_cleanup > DAY_IN_SECONDS ) {
            global $wpdb;
            $table = $wpdb->prefix . 'NEXURA_recaptcha_logs';
            $wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->prefix}NEXURA_recaptcha_logs WHERE timestamp < %s", gmdate( 'Y-m-d H:i:s', strtotime( '-30 days' ) ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            update_option( 'NEXURA_recaptcha_last_cleanup', time() );
        }
    }

    /**
     * Records the user's last login time.
     */
    public function record_last_login( $user_login, $user ) {
        update_user_meta( $user->ID, 'NEXURA_last_login', time() );
    }

    /**
     * Adds the Last Login column to the Users list.
     */
    public function add_last_login_column( $columns ) {
        $columns['nexura_last_login'] = __( 'Last Login', 'nexura-security' );
        return $columns;
    }

    /**
     * Populates the Last Login column.
     */
    public function populate_last_login_column( $value, $column_name, $user_id ) {
        if ( 'nexura_last_login' === $column_name ) {
            $last_login = get_user_meta( $user_id, 'NEXURA_last_login', true );
            if ( ! empty( $last_login ) ) {
                return date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $last_login );
            }
            return __( 'Never', 'nexura-security' );
        }
        return $value;
    }

    /**
     * Hooked on wp_login to check if the user is required to have 2FA.
     */
    public function enforce_2fa_policy( $user_login, $user ) {
        // Enforcing 2FA is a Pro feature
        if ( ! function_exists( 'nexura_is_pro' ) || ! nexura_is_pro() ) {
            return;
        }

        // Skip if IP is allowlisted
        if ( $this->is_ip_allowlisted() ) {
            return;
        }

        // Get roles settings
        $roles_settings = get_option( 'NEXURA_2fa_roles', [] );
        $is_required = false;
        $is_disabled = false;

        foreach ( $user->roles as $role ) {
            $setting = isset( $roles_settings[ $role ] ) ? $roles_settings[ $role ] : 'optional';
            if ( $setting === 'required' ) {
                $is_required = true;
            } elseif ( $setting === 'disabled' ) {
                $is_disabled = true;
            }
        }

        $is_enabled = get_user_meta( $user->ID, 'NEXURA_2fa_enabled', true );

        if ( $is_disabled ) {
            // If disabled by policy but they have it enabled, turn it off.
            if ( $is_enabled === '1' ) {
                update_user_meta( $user->ID, 'NEXURA_2fa_enabled', '0' );
            }
            return;
        }

        if ( $is_required && $is_enabled !== '1' ) {
            // Check grace period
            $grace_period_days = (int) get_option( 'NEXURA_2fa_grace_period', '10' );
            $grace_start = get_user_meta( $user->ID, 'NEXURA_2fa_grace_period_start', true );
            
            if ( empty( $grace_start ) ) {
                $grace_start = time();
                update_user_meta( $user->ID, 'NEXURA_2fa_grace_period_start', $grace_start );
            }

            $days_passed = floor( ( time() - $grace_start ) / DAY_IN_SECONDS );
            
            if ( $days_passed > $grace_period_days ) {
                // Grace period expired. Lock them into a setup screen.
                // We do this by setting a transient and redirecting.
                $token = wp_generate_password( 32, false );
                set_transient( 'NEXURA_2fa_force_setup_' . $token, $user->ID, 3600 );
                wp_logout();
                wp_safe_redirect( admin_url( 'admin.php?page=nexura-login-security&tab=2fa&force_setup=' . $token ) );
                exit;
            }
        }
    }

    /**
     * Checks if a forced setup token is present and acts accordingly.
     */
    public function check_grace_period_enforcement() {
        if ( isset( $_GET['force_setup'] ) && ! is_user_logged_in() ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $token = sanitize_text_field( wp_unslash( $_GET['force_setup'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $user_id = get_transient( 'NEXURA_2fa_force_setup_' . $token );
            if ( $user_id ) {
                $user = get_userdata( $user_id );
                wp_set_current_user( $user->ID, $user->user_login );
                wp_set_auth_cookie( $user->ID, true );
                delete_transient( 'NEXURA_2fa_force_setup_' . $token );
                wp_safe_redirect( admin_url( 'admin.php?page=nexura-login-security&tab=2fa&notice=forced' ) );
                exit;
            }
        }
    }

    /**
     * Checks if the current IP is allowlisted.
     */
    private function is_ip_allowlisted() {
        $allowlist = get_option( 'NEXURA_ip_allowlist', '' );
        if ( empty( $allowlist ) ) {
            return false;
        }

        $ips = explode( "\n", $allowlist );
        $client_ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';

        foreach ( $ips as $ip ) {
            $ip = trim( $ip );
            if ( empty( $ip ) ) continue;

            if ( $ip === $client_ip ) {
                return true;
            }
            
            if ( strpos( $ip, '*' ) !== false ) {
                $pattern = str_replace( '*', '.*', $ip );
                if ( preg_match( '/^' . $pattern . '$/', $client_ip ) ) {
                    return true;
                }
            }
        }

        return false;
    }
}
