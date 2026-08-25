<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>

<div class="nexura-card nexura-fade-in">
    <h2><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg></span> <?php esc_html_e( 'Security Headers Manager', 'nexura-security' ); ?></h2>
    <p class="description" style="margin-bottom: 20px; font-size: 14px;">
        <?php esc_html_e( 'Configure HTTP security headers to protect your website against clickjacking, XSS, MIME sniffing, and other browser-level attacks.', 'nexura-security' ); ?>
    </p>
    <form method="post" action="options.php">
        <?php settings_fields( 'NEXURA_security_headers_group' ); ?>
        <table class="form-table">
            <!-- Master Toggle -->
            <tr>
                <th scope="row"><label for="NEXURA_sh_enable_all"><?php esc_html_e( 'Enable Security Headers', 'nexura-security' ); ?></label></th>
                <td>
                    <label class="nexura-switch" style="margin-top: 5px; margin-bottom: 5px;">
                        <input type="checkbox" id="NEXURA_sh_enable_all" name="NEXURA_sh_enable_all" value="1" <?php checked( get_option( 'NEXURA_sh_enable_all' ), 1 ); ?> />
                        <span class="nexura-slider"></span>
                    </label>
                    <p class="description"><?php esc_html_e( 'Master switch to enable or disable all security headers at once.', 'nexura-security' ); ?></p>
                </td>
            </tr>

            <!-- X-Frame-Options -->
            <tr>
                <th scope="row"><label for="NEXURA_sh_x_frame_options"><?php esc_html_e( 'X-Frame-Options', 'nexura-security' ); ?></label></th>
                <td>
                    <select id="NEXURA_sh_x_frame_options" name="NEXURA_sh_x_frame_options">
                        <option value="SAMEORIGIN" <?php selected( get_option( 'NEXURA_sh_x_frame_options', 'SAMEORIGIN' ), 'SAMEORIGIN' ); ?>><?php esc_html_e( 'SAMEORIGIN (Recommended)', 'nexura-security' ); ?></option>
                        <option value="DENY" <?php selected( get_option( 'NEXURA_sh_x_frame_options' ), 'DENY' ); ?>><?php esc_html_e( 'DENY (Strictest)', 'nexura-security' ); ?></option>
                        <option value="disabled" <?php selected( get_option( 'NEXURA_sh_x_frame_options' ), 'disabled' ); ?>><?php esc_html_e( 'Disabled', 'nexura-security' ); ?></option>
                    </select>
                    <p class="description"><?php esc_html_e( 'Prevents your site from being embedded in iframes on other domains (clickjacking protection).', 'nexura-security' ); ?></p>
                </td>
            </tr>

            <!-- X-XSS-Protection -->
            <tr>
                <th scope="row"><label for="NEXURA_sh_x_xss_protection"><?php esc_html_e( 'X-XSS-Protection', 'nexura-security' ); ?></label></th>
                <td>
                    <label class="nexura-switch" style="margin-top: 5px; margin-bottom: 5px;">
                        <input type="checkbox" id="NEXURA_sh_x_xss_protection" name="NEXURA_sh_x_xss_protection" value="1" <?php checked( get_option( 'NEXURA_sh_x_xss_protection', '1' ), 1 ); ?> />
                        <span class="nexura-slider"></span>
                    </label>
                    <p class="description"><?php esc_html_e( 'Enables the browser built-in XSS filter (1; mode=block).', 'nexura-security' ); ?></p>
                </td>
            </tr>

            <!-- X-Content-Type-Options -->
            <tr>
                <th scope="row"><label for="NEXURA_sh_x_content_type_options"><?php esc_html_e( 'X-Content-Type-Options', 'nexura-security' ); ?></label></th>
                <td>
                    <label class="nexura-switch" style="margin-top: 5px; margin-bottom: 5px;">
                        <input type="checkbox" id="NEXURA_sh_x_content_type_options" name="NEXURA_sh_x_content_type_options" value="1" <?php checked( get_option( 'NEXURA_sh_x_content_type_options', '1' ), 1 ); ?> />
                        <span class="nexura-slider"></span>
                    </label>
                    <p class="description"><?php esc_html_e( 'Prevents browsers from MIME-type sniffing (nosniff). Strongly recommended.', 'nexura-security' ); ?></p>
                </td>
            </tr>

            <?php if ( ! function_exists( 'nexura_is_pro' ) || ! nexura_is_pro() ) : ?>
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
                        <input type="text" value="geolocation=(), microphone=(), camera=()" class="regular-text" disabled />
                        <p class="description"><?php esc_html_e( 'Controls which browser features and APIs can be used.', 'nexura-security' ); ?></p>
                    </td>
                </tr>

                <!-- Content-Security-Policy (CSP) - PRO -->
                <tr style="opacity: 0.7; position: relative;" onclick="document.getElementById('nexura-pro-upgrade-modal').style.display='flex';">
                    <th scope="row">
                        <label><?php esc_html_e( 'Content-Security-Policy', 'nexura-security' ); ?></label>
                        <span style="background: #ec4899; color: white; font-size: 10px; padding: 2px 6px; border-radius: 4px; margin-left: 5px; vertical-align: top;">PRO</span>
                    </th>
                    <td style="pointer-events: none;">
                        <textarea rows="3" class="large-text code" disabled>default-src 'self';</textarea>
                        <p class="description"><?php esc_html_e( 'Advanced protection against XSS and data injection attacks.', 'nexura-security' ); ?></p>
                    </td>
                </tr>
            <?php endif; ?>
        </table>
        <?php submit_button(); ?>
    </form>
</div>
