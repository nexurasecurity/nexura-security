<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Pwned Passwords integration using HaveIBeenPwned API via k-Anonymity
 */
class Pwned_Passwords {

    public function init() {
        if ( ! get_option( 'NEXURA_enable_pwned_check', 0 ) ) {
            return;
        }

        // Intercept login
        add_filter( 'authenticate', [ $this, 'check_pwned_password' ], 30, 3 );
        
        // Intercept password reset
        add_action( 'validate_password_reset', [ $this, 'check_reset_password' ], 10, 2 );
        
        // Intercept profile password change
        add_action( 'user_profile_update_errors', [ $this, 'check_profile_password' ], 10, 3 );
    }

    public function check_reset_password( $errors, $user_data ) {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        if ( isset( $_POST['pass1'] ) && ! empty( $_POST['pass1'] ) ) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
            $password = wp_unslash( $_POST['pass1'] );
            $this->enforce_password_complexity( $password, $errors );
            if ( $this->is_password_pwned( $password ) ) {
                $errors->add( 'NEXURA_pwned_password', '<strong>Nexura Security:</strong> This password has been exposed in a data breach. Please choose a different, secure password.' );
            }
        }
    }

    public function check_profile_password( $errors, $update, $user ) {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        if ( isset( $_POST['pass1'] ) && ! empty( $_POST['pass1'] ) ) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
            $password = wp_unslash( $_POST['pass1'] );
            $this->enforce_password_complexity( $password, $errors );
            if ( $this->is_password_pwned( $password ) ) {
                $errors->add( 'NEXURA_pwned_password', '<strong>Nexura Security:</strong> This password has been exposed in a data breach. Please choose a different, secure password.' );
            }
        }
    }

    private function enforce_password_complexity( $password, $errors ) {
        if ( strlen( $password ) < 8 ) {
            $errors->add( 'NEXURA_pass_length', '<strong>Nexura Security:</strong> Password must be at least 8 characters long.' );
        }
        if ( ! preg_match( '/[A-Z]/', $password ) ) {
            $errors->add( 'NEXURA_pass_upper', '<strong>Nexura Security:</strong> Password must contain at least one uppercase letter.' );
        }
        if ( ! preg_match( '/[a-z]/', $password ) ) {
            $errors->add( 'NEXURA_pass_lower', '<strong>Nexura Security:</strong> Password must contain at least one lowercase letter.' );
        }
        if ( ! preg_match( '/[0-9]/', $password ) ) {
            $errors->add( 'NEXURA_pass_number', '<strong>Nexura Security:</strong> Password must contain at least one number.' );
        }
        if ( ! preg_match( '/[^a-zA-Z0-9]/', $password ) ) {
            $errors->add( 'NEXURA_pass_special', '<strong>Nexura Security:</strong> Password must contain at least one special character.' );
        }
    }

    private function is_password_pwned( $password ) {
        $hash = strtoupper( sha1( $password ) );
        $prefix = substr( $hash, 0, 5 );
        $suffix = substr( $hash, 5 );
        $url = 'https://api.pwnedpasswords.com/range/' . $prefix;
        $response = wp_remote_get( $url, [ 'timeout' => 3 ] );
        
        if ( ! is_wp_error( $response ) && wp_remote_retrieve_response_code( $response ) === 200 ) {
            $body = wp_remote_retrieve_body( $response );
            $lines = explode( "\n", str_replace( "\r", "", $body ) );
            foreach ( $lines as $line ) {
                if ( empty( $line ) ) continue;
                $parts = explode( ':', $line );
                if ( count( $parts ) !== 2 ) continue;
                if ( trim( $parts[0] ) === $suffix ) {
                    return true;
                }
            }
        }
        return false;
    }

    public function check_pwned_password( $user, $username, $password ) {
        if ( is_wp_error( $user ) || empty( $password ) ) {
            return $user;
        }

        if ( $this->is_password_pwned( $password ) ) {
            if ( class_exists( '\\Nexura_Security\\Logger' ) ) {
                if ( class_exists( '\Nexura_Security\Logger' ) ) {
                    \Nexura_Security\Logger::log( 'Blocked login for user ' . $username . ' due to pwned password.' );
                }
            }
            return new \WP_Error(
                'NEXURA_pwned_password',
                '<strong>Nexura Security:</strong> The password you entered has been exposed in a public data breach. For your security, login is blocked. Please <a href="' . esc_url( wp_lostpassword_url() ) . '">reset your password</a>.'
            );
        }

        return $user;
    }
}
