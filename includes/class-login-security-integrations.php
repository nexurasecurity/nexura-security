<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Login_Security_Integrations
 * 
 * Handles WooCommerce integration and 2FA shortcodes.
 */
class Login_Security_Integrations {

    public function init() {
        if ( get_option( 'NEXURA_2fa_shortcode', '0' ) === '1' ) {
            add_shortcode( 'nexura_2fa_management', [ $this, 'render_shortcode' ] );
        }

        if ( get_option( 'NEXURA_wc_integration', '0' ) === '1' ) {
            // Future: Hook into WooCommerce login/registration for reCAPTCHA/2FA
        }

        if ( get_option( 'NEXURA_wc_account_menu', '0' ) === '1' && class_exists( 'WooCommerce' ) ) {
            add_filter( 'woocommerce_account_menu_items', [ $this, 'add_wc_account_menu_item' ] );
            add_action( 'init', [ $this, 'add_wc_endpoint' ] );
            add_action( 'woocommerce_account_nexura-2fa_endpoint', [ $this, 'render_wc_endpoint_content' ] );
        }
    }

    /**
     * Renders the 2FA management shortcode.
     */
    public function render_shortcode() {
        if ( ! is_user_logged_in() ) {
            return '<p>' . esc_html__( 'You must be logged in to manage Two-Factor Authentication.', 'nexura-security' ) . '</p>';
        }

        // We need the shortcode to look like the admin UI but self-contained
        // Load the admin script and styles for this shortcode
        wp_enqueue_script( 'nexura-qrcode', NEXURA_PLUGIN_URL . 'admin/js/qrcode.min.js', [], NEXURA_VERSION, true );
        // Only enqueue admin-script if not already enqueued (admin pages enqueue it with chart.js support)
        if ( ! wp_script_is( 'nexura-admin-script', 'enqueued' ) ) {
            wp_enqueue_script( 'nexura-admin-script', NEXURA_PLUGIN_URL . 'admin/js/admin-script.js', [ 'jquery', 'nexura-qrcode' ], NEXURA_VERSION, true );
        }
        if ( ! wp_style_is( 'nexura-admin-style', 'enqueued' ) ) {
            wp_enqueue_style( 'nexura-admin-style', NEXURA_PLUGIN_URL . 'admin/css/admin-style.css', [], NEXURA_VERSION );
        }

        // Add frontend specific overrides
        $custom_css = "
            .nexura-frontend-wrap { margin: 0; min-height: auto; background: transparent; padding: 0; }
            .nexura-frontend-wrap .nexura-card { margin: 0; box-shadow: none; border: 1px solid var(--nexura-border); }
            .nexura-frontend-wrap .notice { display: none !important; }
        ";
        wp_add_inline_style( 'nexura-admin-style', $custom_css );
        wp_enqueue_style( 'nexura-admin-style', NEXURA_PLUGIN_URL . 'admin/css/admin-style.css', [], NEXURA_VERSION );

        wp_localize_script( 'nexura-admin-script', 'NEXURA_ajax', [
            'rest_url'       => esc_url_raw( rest_url() ),
            'nonce'          => wp_create_nonce( 'wp_rest' )
        ] );

        $is_single_column = get_option( 'NEXURA_wc_single_column', '1' ) === '1';

        ob_start();
        ?>
        <div class="nexura-wrap nexura-frontend-wrap nexura-security-front-end <?php echo $is_single_column ? 'nexura-single-column' : ''; ?>">
            <?php require NEXURA_PLUGIN_DIR . 'admin/views/2fa-settings.php'; ?>
        </div>
        <?php
        return ob_get_clean();
    }

    /**
     * Adds the 2FA menu item to WooCommerce My Account.
     */
    public function add_wc_account_menu_item( $items ) {
        $items['nexura-2fa'] = __( 'Two-Factor Authentication', 'nexura-security' );
        return $items;
    }

    /**
     * Adds the WooCommerce endpoint for 2FA.
     */
    public function add_wc_endpoint() {
        add_rewrite_endpoint( 'nexura-2fa', EP_PAGES );
    }

    /**
     * Renders the WooCommerce endpoint content.
     */
    public function render_wc_endpoint_content() {
        echo $this->render_shortcode(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
    }
}
