<?php
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
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
            <tr>
                <th scope="row"><label for="block_php_uploads"><?php esc_html_e( 'Block PHP Execution in Uploads', 'nexura-security' ); ?></label></th>
                <td>
                    <label class="nexura-switch" style="margin-top: 5px; margin-bottom: 5px;">
                        <input type="checkbox" id="block_php_uploads" name="block_php_uploads" value="1" <?php checked( get_option( 'block_php_uploads' ), 1 ); ?> />
                        <span class="nexura-slider"></span>
                    </label>
                    <p class="description"><?php esc_html_e( 'Places a .htaccess file in wp-content/uploads/ to prevent attackers from executing uploaded PHP files.', 'nexura-security' ); ?></p>
                </td>
            </tr>
        </table>
        <?php submit_button(); ?>
    </form>
</div>

<div class="nexura-card nexura-fade-in" style="animation-delay: 0.15s; margin-top: 20px;">
    <h2><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg></span> <?php esc_html_e( 'File Permissions Check', 'nexura-security' ); ?></h2>
    <p><?php esc_html_e( 'We automatically checked your core WordPress directories. Incorrect permissions can allow hackers to modify your site.', 'nexura-security' ); ?></p>
    
    <table class="wp-list-table widefat striped" style="margin-top: 15px;">
        <thead>
            <tr>
                <th><?php esc_html_e( 'Path', 'nexura-security' ); ?></th>
                <th><?php esc_html_e( 'Current Permissions', 'nexura-security' ); ?></th>
                <th><?php esc_html_e( 'Recommended', 'nexura-security' ); ?></th>
                <th><?php esc_html_e( 'Status', 'nexura-security' ); ?></th>
            </tr>
        </thead>
        <tbody>
            <?php
            $paths_to_check = [
                ABSPATH => [ 'type' => 'dir', 'recommended' => '0755' ],
                ABSPATH . 'wp-includes' => [ 'type' => 'dir', 'recommended' => '0755' ],
                WP_CONTENT_DIR => [ 'type' => 'dir', 'recommended' => '0755' ],
                ABSPATH . 'wp-config.php' => [ 'type' => 'file', 'recommended' => '0644' ], // Sometimes 0600 or 0400 is recommended depending on the host
                ABSPATH . '.htaccess' => [ 'type' => 'file', 'recommended' => '0644' ]
            ];

            foreach ( $paths_to_check as $path => $info ) {
                if ( ! file_exists( $path ) ) continue;

                $perms = substr( sprintf( '%o', fileperms( $path ) ), -4 );
                // Strict check: if dir, 755 or stricter. If file, 644 or stricter.
                $is_safe = false;
                if ( $info['type'] === 'dir' ) {
                    $is_safe = ( $perms === '0755' || $perms === '0750' || $perms === '0700' );
                } else {
                    $is_safe = ( $perms === '0644' || $perms === '0640' || $perms === '0600' || $perms === '0400' );
                }

                $status_html = $is_safe ? '<span style="color: #10b981; font-weight: bold; display: inline-flex; align-items: center; gap: 4px;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"></path></svg> Secure</span>' : '<span style="color: #ef4444; font-weight: bold; display: inline-flex; align-items: center; gap: 4px;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg> Insecure</span>';
                ?>
                <tr>
                    <td><code><?php echo esc_html( str_replace( ABSPATH, '', $path ) ?: '/' ); ?></code></td>
                    <td><code><?php echo esc_html( $perms ); ?></code></td>
                    <td><code><?php echo esc_html( $info['recommended'] ); ?></code></td>
                    <td><?php echo $status_html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></td>
                </tr>
                <?php
            }
            ?>
        </tbody>
    </table>
    <p class="description" style="margin-top: 15px;">
        <?php esc_html_e( 'Note: Depending on your server configuration (e.g. suPHP, FastCGI), strict permissions like 0600 for wp-config.php may be required. If a path is marked as insecure, use your hosting control panel or FTP to correct it.', 'nexura-security' ); ?>
    </p>
</div>
