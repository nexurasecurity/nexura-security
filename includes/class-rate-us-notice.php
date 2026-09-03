<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class Rate_Us_Notice
 *
 * Shows a friendly "Rate Us" notice in the WP admin after the plugin
 * has been active for 14 days. Complies with WordPress.org guidelines:
 * - Never shown on first install
 * - User can permanently dismiss it
 * - Not intrusive (shows once per session after dismissal attempt)
 */
class Rate_Us_Notice {

    const OPT_INSTALLED_ON = 'NEXURA_installed_on';
    const OPT_DISMISSED    = 'NEXURA_rate_notice_dismissed';
    const DAYS_BEFORE_SHOW = 14;

    public function __construct() {
        add_action( 'admin_notices', [ $this, 'show_notice' ] );
        add_action( 'wp_ajax_nexura_dismiss_rate_notice', [ $this, 'ajax_dismiss' ] );
        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_dismiss_script' ] );
    }

    /**
     * Records the installation timestamp (runs on activation).
     * Called from class-activator.php
     */
    public static function record_install_date() {
        if ( ! get_option( self::OPT_INSTALLED_ON ) ) {
            update_option( self::OPT_INSTALLED_ON, time(), false );
        }
    }

    /**
     * Shows the notice if conditions are met.
     */
    public function show_notice() {
        // Already dismissed permanently
        if ( get_option( self::OPT_DISMISSED ) ) {
            return;
        }

        // Not on a Nexura admin page
        $screen = get_current_screen();
        if ( ! $screen || strpos( $screen->id, 'nexura' ) === false ) {
            return;
        }

        $installed_on = (int) get_option( self::OPT_INSTALLED_ON, 0 );
        if ( ! $installed_on ) {
            return;
        }

        $days_since = ( time() - $installed_on ) / DAY_IN_SECONDS;

        // Not yet 14 days
        if ( $days_since < self::DAYS_BEFORE_SHOW ) {
            return;
        }

        $review_url   = 'https://wordpress.org/support/plugin/nexura-security/reviews/#new-post';
        $dismiss_url  = wp_nonce_url(
            add_query_arg( 'nexura_dismiss_rate', '1' ),
            'nexura_dismiss_rate'
        );
        ?>
        <div id="nexura-rate-notice" class="notice notice-info" style="
            border-left: 4px solid #6c5ce7;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e2e8f0;
            border-radius: 0 8px 8px 0;
            padding: 16px 20px;
            display: flex;
            align-items: center;
            gap: 20px;
            position: relative;
        ">
            <span style="font-size: 36px; line-height: 1;">⭐</span>
            <div style="flex: 1;">
                <strong style="font-size: 15px; color: #fff; display: block; margin-bottom: 6px;">
                    <?php esc_html_e( 'Enjoying Nexura Security?', 'nexura-security' ); ?>
                </strong>
                <p style="margin: 0 0 10px 0; color: #94a3b8; font-size: 13px;">
                    <?php esc_html_e( 'You have been using Nexura Security for over 2 weeks. If it has helped protect your site, please take a moment to leave a quick review on WordPress.org — it really helps us grow!', 'nexura-security' ); ?>
                </p>
                <div style="display: flex; gap: 12px; flex-wrap: wrap;">
                    <a href="<?php echo esc_url( $review_url ); ?>"
                       target="_blank"
                       id="nexura-rate-now"
                       style="
                           background: linear-gradient(90deg, #6c5ce7, #a29bfe);
                           color: #fff;
                           padding: 7px 16px;
                           border-radius: 6px;
                           text-decoration: none;
                           font-size: 13px;
                           font-weight: 600;
                       ">
                        ⭐ <?php esc_html_e( 'Rate Nexura Security', 'nexura-security' ); ?>
                    </a>
                    <a href="#"
                       id="nexura-rate-later"
                       style="color: #64748b; font-size: 13px; padding: 7px 0; text-decoration: none;"
                       data-nonce="<?php echo esc_attr( wp_create_nonce( 'nexura_dismiss_rate_nonce' ) ); ?>">
                        <?php esc_html_e( 'Maybe later', 'nexura-security' ); ?>
                    </a>
                    <a href="#"
                       id="nexura-rate-never"
                       style="color: #475569; font-size: 13px; padding: 7px 0; text-decoration: none;"
                       data-nonce="<?php echo esc_attr( wp_create_nonce( 'nexura_dismiss_rate_nonce' ) ); ?>">
                        <?php esc_html_e( 'I already did / Don\'t show again', 'nexura-security' ); ?>
                    </a>
                </div>
            </div>
            <button type="button"
                    id="nexura-rate-close"
                    data-nonce="<?php echo esc_attr( wp_create_nonce( 'nexura_dismiss_rate_nonce' ) ); ?>"
                    style="
                        position: absolute;
                        top: 12px;
                        right: 14px;
                        background: none;
                        border: none;
                        color: #64748b;
                        cursor: pointer;
                        font-size: 18px;
                        line-height: 1;
                        padding: 0;
                    "
                    title="<?php esc_attr_e( 'Dismiss', 'nexura-security' ); ?>">
                ✕
            </button>
        </div>
        <?php
    }

    /**
     * Enqueues the inline dismiss script.
     */
    public function enqueue_dismiss_script( $hook ) {
        if ( strpos( $hook, 'nexura' ) === false ) {
            return;
        }
        ?>
        <script>
        (function() {
            function nexuraDismissRate(permanent) {
                var xhr = new XMLHttpRequest();
                xhr.open('POST', '<?php echo esc_url( admin_url( 'admin-ajax.php' ) ); ?>');
                xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
                var nonce = document.querySelector('#nexura-rate-notice [data-nonce]');
                xhr.send('action=nexura_dismiss_rate_notice&permanent=' + (permanent ? '1' : '0') + '&_nonce=' + (nonce ? nonce.dataset.nonce : ''));
                var el = document.getElementById('nexura-rate-notice');
                if (el) el.style.display = 'none';
            }

            document.addEventListener('DOMContentLoaded', function() {
                var rateLater = document.getElementById('nexura-rate-later');
                var rateNever = document.getElementById('nexura-rate-never');
                var rateClose = document.getElementById('nexura-rate-close');
                var rateNow   = document.getElementById('nexura-rate-now');

                if (rateLater) rateLater.addEventListener('click', function(e) {
                    e.preventDefault();
                    nexuraDismissRate(false);
                });
                if (rateNever) rateNever.addEventListener('click', function(e) {
                    e.preventDefault();
                    nexuraDismissRate(true);
                });
                if (rateClose) rateClose.addEventListener('click', function(e) {
                    e.preventDefault();
                    nexuraDismissRate(false);
                });
                if (rateNow) rateNow.addEventListener('click', function() {
                    nexuraDismissRate(true); // Clicked to rate — dismiss permanently
                });
            });
        })();
        </script>
        <?php
    }

    /**
     * AJAX handler to dismiss the notice.
     */
    public function ajax_dismiss() {
        if ( ! check_ajax_referer( 'nexura_dismiss_rate_nonce', '_nonce', false ) ) {
            wp_die( -1 );
        }
        if ( ! \Nexura_Security::can_manage_security() ) {
            wp_die( -1 );
        }

        $permanent = isset( $_POST['permanent'] ) && '1' === $_POST['permanent']; // phpcs:ignore WordPress.Security.NonceVerification.Missing

        if ( $permanent ) {
            update_option( self::OPT_DISMISSED, true, false );
        }

        wp_send_json_success( [ 'permanent' => $permanent ] );
    }
}

