<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>


<div class="nexura-card nexura-fade-in">
    <h2><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg></span> <?php esc_html_e( 'Hardening Rules', 'nexura-security' ); ?></h2>
    <form method="post" action="options.php">
        <?php settings_fields( 'NEXURA_hardening_group' ); ?>
        <table class="form-table">
            <tr>
                <th scope="row"><label for="NEXURA_disable_file_editor"><?php esc_html_e( 'Disable File Editor', 'nexura-security' ); ?></label></th>
                <td>
                    <label class="nexura-switch" style="margin-top: 5px; margin-bottom: 5px;">
                        <input type="checkbox" id="NEXURA_disable_file_editor" name="NEXURA_disable_file_editor" value="1" <?php checked( get_option( 'NEXURA_disable_file_editor' ), 1 ); ?> />
                        <span class="nexura-slider"></span>
                    </label>
                    <p class="description"><?php esc_html_e( 'Disables the theme and plugin editor in the WordPress dashboard.', 'nexura-security' ); ?></p>
                    <p class="description" style="color: #ef4444; font-weight: 500; font-size: 13px; margin-top: 5px;">
                        <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="vertical-align: text-bottom;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg> <?php esc_html_e( 'Warning: This restricts direct code editing. Ensure you have FTP/SFTP access before enabling.', 'nexura-security' ); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><label for="NEXURA_add_security_headers"><?php esc_html_e( 'Add Security Headers', 'nexura-security' ); ?></label></th>
                <td>
                    <label class="nexura-switch" style="margin-top: 5px; margin-bottom: 5px;">
                        <input type="checkbox" id="NEXURA_add_security_headers" name="NEXURA_add_security_headers" value="1" <?php checked( get_option( 'NEXURA_add_security_headers' ), 1 ); ?> />
                        <span class="nexura-slider"></span>
                    </label>
                    <p class="description"><?php esc_html_e( 'Adds X-Frame-Options, X-XSS-Protection, and other security headers.', 'nexura-security' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><label for="NEXURA_restrict_rest_api"><?php esc_html_e( 'Restrict REST API', 'nexura-security' ); ?></label></th>
                <td>
                    <label class="nexura-switch" style="margin-top: 5px; margin-bottom: 5px;">
                        <input type="checkbox" id="NEXURA_restrict_rest_api" name="NEXURA_restrict_rest_api" value="1" <?php checked( get_option( 'NEXURA_restrict_rest_api' ), 1 ); ?> />
                        <span class="nexura-slider"></span>
                    </label>
                    <p class="description"><?php esc_html_e( 'Restrict REST API access to logged-in users only.', 'nexura-security' ); ?></p>
                    <p class="description" style="color: #ef4444; font-weight: 500; font-size: 13px; margin-top: 5px;">
                        <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="vertical-align: text-bottom;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg> <?php esc_html_e( 'Warning: This may break WooCommerce, Gutenberg block editor, or third-party apps that rely on public API endpoints. Test your site after enabling.', 'nexura-security' ); ?>
                    </p>
                </td>
            </tr>
        </table>
        <?php submit_button(); ?>
    </form>
</div>
