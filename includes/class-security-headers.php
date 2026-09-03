<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Security_Headers
 * 
 * Manages HTTP Security Headers (CSP, HSTS, X-Frame-Options, etc.).
 */
class Security_Headers {

    public function init() {
        add_action( 'send_headers', [ $this, 'add_security_headers' ] );
        add_action( 'admin_init', [ $this, 'migrate_old_settings' ] );
        add_action( 'nexura_pro_security_headers_fields', [ $this, 'render_locked_pro_fields' ] );
    }

    /**
     * Renders locked Pro fields for upsell in the Free version.
     */
    public function render_locked_pro_fields() {
        if ( function_exists( 'nexura_is_pro' ) && nexura_is_pro() ) {
            return;
        }
        ?>
        <!-- Strict-Transport-Security (HSTS) - PRO -->
        <tr style="opacity: 0.7; position: relative;" onclick="document.getElementById('nexura-pro-upgrade-modal').style.display='flex';">
            <th scope="row">
                <label><?php esc_html_e( 'Strict-Transport-Security (HSTS)', 'nexura-security' ); ?></label>
                <span style="background: #ec4899; color: white; font-size: 10px; padding: 2px 6px; border-radius: 4px; margin-left: 5px; vertical-align: top;">PRO</span>
            </th>
            <td style="pointer-events: none;">
                <select disabled>
                    <option value="disabled" selected><?php esc_html_e( 'Disabled', 'nexura-security' ); ?></option>
                </select>
                <p class="description"><?php esc_html_e( 'Forces browsers to always use HTTPS.', 'nexura-security' ); ?></p>
            </td>
        </tr>

        <!-- Referrer-Policy - PRO -->
        <tr style="opacity: 0.7; position: relative;" onclick="document.getElementById('nexura-pro-upgrade-modal').style.display='flex';">
            <th scope="row">
                <label><?php esc_html_e( 'Referrer-Policy', 'nexura-security' ); ?></label>
                <span style="background: #ec4899; color: white; font-size: 10px; padding: 2px 6px; border-radius: 4px; margin-left: 5px; vertical-align: top;">PRO</span>
            </th>
            <td style="pointer-events: none;">
                <select disabled>
                    <option value="disabled" selected><?php esc_html_e( 'Disabled', 'nexura-security' ); ?></option>
                </select>
                <p class="description"><?php esc_html_e( 'Controls how much referrer information is included with requests.', 'nexura-security' ); ?></p>
            </td>
        </tr>

        <!-- Permissions-Policy - PRO -->
        <tr style="opacity: 0.7; position: relative;" onclick="document.getElementById('nexura-pro-upgrade-modal').style.display='flex';">
            <th scope="row">
                <label><?php esc_html_e( 'Permissions-Policy', 'nexura-security' ); ?></label>
                <span style="background: #ec4899; color: white; font-size: 10px; padding: 2px 6px; border-radius: 4px; margin-left: 5px; vertical-align: top;">PRO</span>
            </th>
            <td style="pointer-events: none;">
                <input type="text" value="camera=(), microphone=(), geolocation=()" class="regular-text" style="width: 100%; max-width: 600px;" disabled />
                <p class="description"><?php esc_html_e( 'Controls browser features like camera, microphone, and geolocation.', 'nexura-security' ); ?></p>
            </td>
        </tr>

        <!-- Content-Security-Policy (CSP) - PRO -->
        <tr style="opacity: 0.7; position: relative;" onclick="document.getElementById('nexura-pro-upgrade-modal').style.display='flex';">
            <th scope="row">
                <label><?php esc_html_e( 'Content-Security-Policy (CSP)', 'nexura-security' ); ?></label>
                <span style="background: #ec4899; color: white; font-size: 10px; padding: 2px 6px; border-radius: 4px; margin-left: 5px; vertical-align: top;">PRO</span>
            </th>
            <td style="pointer-events: none;">
                <textarea rows="3" class="large-text" style="max-width: 600px;" disabled></textarea>
                <p class="description"><?php esc_html_e( 'Advanced: Define a Content-Security-Policy. Helps prevent cross-site scripting attacks.', 'nexura-security' ); ?></p>
            </td>
        </tr>
        <?php
    }

    /**
     * Migrates the old basic hardening setting to the new manager.
     */
    public function migrate_old_settings() {
        $old_setting = get_option( 'NEXURA_add_security_headers' );
        if ( $old_setting !== false ) {
            if ( $old_setting == '1' ) {
                update_option( 'NEXURA_sh_enable_all', '1' );
                update_option( 'NEXURA_sh_x_frame_options', 'SAMEORIGIN' );
                update_option( 'NEXURA_sh_x_xss_protection', '1' );
                update_option( 'NEXURA_sh_x_content_type_options', '1' );
                update_option( 'NEXURA_sh_strict_transport_security', 'max-age=31536000; includeSubDomains' );
            }
            delete_option( 'NEXURA_add_security_headers' );
        }
    }

    /**
     * Outputs the security headers.
     */
    public function add_security_headers() {
        if ( get_option( 'NEXURA_sh_enable_all', '0' ) !== '1' || headers_sent() ) {
            return;
        }

        // X-Frame-Options
        $xfo = get_option( 'NEXURA_sh_x_frame_options', 'SAMEORIGIN' );
        if ( $xfo !== 'disabled' && ! empty( $xfo ) ) {
            header( 'X-Frame-Options: ' . $xfo );
        }

        // X-XSS-Protection
        if ( get_option( 'NEXURA_sh_x_xss_protection', '1' ) === '1' ) {
            header( 'X-XSS-Protection: 1; mode=block' );
        }

        // X-Content-Type-Options
        if ( get_option( 'NEXURA_sh_x_content_type_options', '1' ) === '1' ) {
            header( 'X-Content-Type-Options: nosniff' );
        }
        
        // Note: Strict-Transport-Security (HSTS), Referrer-Policy, 
        // Permissions-Policy, and Content-Security-Policy (CSP) are 
        // Pro-only features and are handled by the Pro version via
        // Nexura_Security\Security_Headers_Pro class.
    }
}
