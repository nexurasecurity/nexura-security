<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Magic_Link
 * 
 * Provides passwordless login via email.
 */
class Magic_Link {

    public function init() {
        if ( ! get_option( 'NEXURA_enable_magic_link', 0 ) ) {
            return;
        }

        add_action( 'login_form', [ $this, 'add_magic_link_button' ] );
        add_action( 'login_form_NEXURA_magic_link', [ $this, 'process_magic_link_request' ] );
        add_action( 'login_init', [ $this, 'verify_magic_link' ] );
        add_action( 'template_redirect', [ $this, 'verify_magic_link' ] );
    }

    public function add_magic_link_button() {
        /*
         * site_url( 'wp-login.php' ) is the WordPress-recommended method for
         * referencing the login page URL. It correctly handles custom login
         * page configurations and SSL schemes.
         */
        $url = site_url( 'wp-login.php?action=NEXURA_magic_link', 'login' );
        echo '<p style="margin-bottom: 20px; text-align: center;">';
        echo '<a href="' . esc_url( $url ) . '" class="button button-secondary" style="width: 100%; text-align: center; display: flex; align-items: center; justify-content: center; gap: 8px; padding: 5px;">';
        echo '<img src="' . esc_url( NEXURA_PLUGIN_URL . 'admin/img/icon.png' ) . '" alt="Nexura Icon" style="width: 30px; height: 30px;">';
        echo esc_html__( 'Log in with Magic Link', 'nexura-security' ) . '</a>';
        echo '</p>';
    }

    public function process_magic_link_request() {
        if ( isset( $_SERVER['REQUEST_METHOD'] ) && $_SERVER['REQUEST_METHOD'] === 'POST' && isset( $_POST['user_login'] ) ) {
            if ( ! isset( $_POST['NEXURA_magic_link_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['NEXURA_magic_link_nonce'] ) ), 'NEXURA_magic_link_action' ) ) {
                wp_die( esc_html__( 'Security check failed.', 'nexura-security' ) );
            }

            $ip = '127.0.0.1';
            if ( isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
                $ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
            } elseif ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
                $ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
            }
            $ip = filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '127.0.0.1';

            $rate_limit_key = 'NEXURA_magic_link_rate_' . md5($ip);
            $attempts = get_transient( $rate_limit_key );
            if ( $attempts === false ) $attempts = 0;

            if ( $attempts >= 3 ) {
                wp_die( esc_html__( 'Too many requests. Please try again in 15 minutes.', 'nexura-security' ) );
            }
            set_transient( $rate_limit_key, $attempts + 1, 15 * MINUTE_IN_SECONDS );

            $user_login = sanitize_text_field( wp_unslash( $_POST['user_login'] ) );
            $user = get_user_by( 'login', $user_login );
            if ( ! $user ) {
                $user = get_user_by( 'email', $user_login );
            }

            if ( $user ) {
                // Account-level rate limit: prevents attacker from hammering
                // the same account from different IPs.
                $account_rate_key = 'NEXURA_magic_link_acct_' . $user->ID;
                $account_attempts = get_transient( $account_rate_key );
                if ( $account_attempts === false ) $account_attempts = 0;
                if ( $account_attempts >= 3 ) {
                    // Still show generic success to avoid user enumeration
                    login_header( __( 'Magic Link Sent', 'nexura-security' ) );
                    echo '<p class="message">' . esc_html__( 'If an account exists, a magic link has been sent to your email address.', 'nexura-security' ) . '</p>';
                    login_footer();
                    exit;
                }
                set_transient( $account_rate_key, $account_attempts + 1, 15 * MINUTE_IN_SECONDS );

                $token = wp_generate_password( 32, false );
                // 10-minute expiry — shorter window reduces attack surface
                set_transient( 'NEXURA_magic_link_' . $token, $user->ID, 10 * MINUTE_IN_SECONDS );

                $link = add_query_arg( [ 'NEXURA_magic_token' => $token ], site_url( 'wp-login.php' ) );

                $subject = __( 'Your Magic Login Link', 'nexura-security' );
                /* translators: %s: Magic login link URL */
                $message = sprintf( esc_html__( 'Click the following link to log in to your account. This link will expire in 10 minutes: %s', 'nexura-security' ), "\n\n" . $link );
                
                wp_mail( $user->user_email, $subject, $message );
            }

            // Always show success to prevent user enumeration
            login_header( __( 'Magic Link Sent', 'nexura-security' ) );
            echo '<p class="message">' . esc_html__( 'If an account exists, a magic link has been sent to your email address.', 'nexura-security' ) . '</p>';
            login_footer();
            exit;
        }

        login_header( __( 'Magic Link Login', 'nexura-security' ) );
        ?>
        <form name="magic_link_form" id="magic_link_form" action="<?php echo esc_url( site_url( 'wp-login.php?action=NEXURA_magic_link', 'login_post' ) ); ?>" method="post">
            <?php wp_nonce_field( 'NEXURA_magic_link_action', 'NEXURA_magic_link_nonce' ); ?>
            <p>
                <label for="user_login"><?php esc_html_e( 'Username or Email Address', 'nexura-security' ); ?></label>
                <input type="text" name="user_login" id="user_login" class="input" value="" size="20" required />
            </p>
            <p class="submit">
                <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Send Magic Link', 'nexura-security' ); ?>" />
            </p>
        </form>
        <p id="nav">
            <a href="<?php echo esc_url( wp_login_url() ); ?>"><?php esc_html_e( 'Log in with password', 'nexura-security' ); ?></a>
        </p>
        <?php
        login_footer();
        exit;
    }

    public function verify_magic_link() {
        if ( isset( $_GET['NEXURA_magic_token'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $token = sanitize_text_field( wp_unslash( $_GET['NEXURA_magic_token'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $user_id = get_transient( 'NEXURA_magic_link_' . $token );

            // Immediately delete the transient to prevent concurrent race condition logins and clean up invalid attempts
            delete_transient( 'NEXURA_magic_link_' . $token );

            if ( $user_id ) {
                $user = get_user_by( 'id', $user_id );
                if ( $user ) {
                    wp_set_current_user( $user->ID, $user->user_login );
                    // remember=false: session-only cookie (expires on browser close).
                    // secure=is_ssl(): enforce HTTPS-only cookie on SSL sites.
                    wp_set_auth_cookie( $user->ID, false, is_ssl() );
                    do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
                    wp_safe_redirect( admin_url() );
                    exit;
                }
            } else {
                wp_die( esc_html__( 'This magic link has expired or is invalid. Please request a new one.', 'nexura-security' ), esc_html__( 'Invalid Link', 'nexura-security' ) );
            }
        }
    }
}
