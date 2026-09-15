<?php
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>

<div class="nexura-card nexura-fade-in">
    <h2><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg></span> <?php esc_html_e( 'Hardening Rules', 'nexura-security' ); ?></h2>

    <div id="nexura-hardening-toast" style="display:none;position:fixed;bottom:28px;right:28px;z-index:99999;background:#1e293b;border:1px solid rgba(255,255,255,0.1);border-radius:10px;padding:12px 20px;color:#f1f5f9;font-size:13px;align-items:center;gap:10px;box-shadow:0 8px 32px rgba(0,0,0,0.4);" aria-live="polite"></div>

    <input type="hidden" id="nexura-hardening-nonce" value="<?php echo esc_attr( wp_create_nonce( 'nexura_hardening_toggle' ) ); ?>" />

    <table class="form-table" id="nexura-hardening-table">
        <tr>
            <th scope="row"><label for="NEXURA_disable_file_editor"><?php esc_html_e( 'Disable File Editor', 'nexura-security' ); ?></label></th>
            <td>
                <label class="nexura-switch" style="margin-top:5px;margin-bottom:5px;">
                    <input type="checkbox" class="nexura-hardening-toggle" id="NEXURA_disable_file_editor"
                        data-option="NEXURA_disable_file_editor"
                        value="1" <?php checked( get_option( 'NEXURA_disable_file_editor' ), 1 ); ?> />
                    <span class="nexura-slider"></span>
                </label>
                <p class="description"><?php esc_html_e( 'Disables the theme and plugin editor in the WordPress dashboard.', 'nexura-security' ); ?></p>
                <p class="description" style="color:#ef4444;font-weight:500;font-size:13px;margin-top:5px;">
                    <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="vertical-align:text-bottom;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                    <?php esc_html_e( 'Warning: Ensure you have FTP/SFTP access before enabling.', 'nexura-security' ); ?>
                </p>
            </td>
        </tr>

        <tr>
            <th scope="row"><label for="NEXURA_restrict_rest_api"><?php esc_html_e( 'Restrict REST API', 'nexura-security' ); ?></label></th>
            <td>
                <label class="nexura-switch" style="margin-top:5px;margin-bottom:5px;">
                    <input type="checkbox" class="nexura-hardening-toggle" id="NEXURA_restrict_rest_api"
                        data-option="NEXURA_restrict_rest_api"
                        value="1" <?php checked( get_option( 'NEXURA_restrict_rest_api' ), 1 ); ?> />
                    <span class="nexura-slider"></span>
                </label>
                <p class="description"><?php esc_html_e( 'Restrict REST API access to logged-in users only.', 'nexura-security' ); ?></p>
                <p class="description" style="color:#ef4444;font-weight:500;font-size:13px;margin-top:5px;">
                    <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="vertical-align:text-bottom;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                    <?php esc_html_e( 'Warning: May break WooCommerce, Gutenberg or third-party apps. Test after enabling.', 'nexura-security' ); ?>
                </p>
            </td>
        </tr>

        <tr>
            <th scope="row"><label for="block_php_uploads"><?php esc_html_e( 'Block PHP Execution in Uploads', 'nexura-security' ); ?></label></th>
            <td>
                <label class="nexura-switch" style="margin-top:5px;margin-bottom:5px;">
                    <input type="checkbox" class="nexura-hardening-toggle" id="block_php_uploads"
                        data-option="block_php_uploads"
                        value="1" <?php checked( get_option( 'block_php_uploads' ), 1 ); ?> />
                    <span class="nexura-slider"></span>
                </label>
                <p class="description"><?php esc_html_e( 'Places a .htaccess in wp-content/uploads/ to prevent PHP execution from uploaded files.', 'nexura-security' ); ?></p>
            </td>
        </tr>
    </table>
</div>

<div class="nexura-card nexura-fade-in" style="animation-delay:0.15s;margin-top:20px;">
    <h2><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg></span> <?php esc_html_e( 'File Permissions Check', 'nexura-security' ); ?></h2>
    <p><?php esc_html_e( 'We automatically checked your core WordPress directories. Incorrect permissions can allow hackers to modify your site.', 'nexura-security' ); ?></p>

    <input type="hidden" id="nexura-perm-nonce" value="<?php echo esc_attr( wp_create_nonce( 'nexura_fix_permission' ) ); ?>" />

    <?php
    // Load previously acknowledged (fixed) paths
    $nexura_acknowledged = get_option( 'nexura_acknowledged_perms', [] );

    $nexura_paths_to_check = [
        ABSPATH                   => [ 'type' => 'dir',  'recommended' => '0755' ],
        ABSPATH . 'wp-admin'      => [ 'type' => 'dir',  'recommended' => '0755' ],
        ABSPATH . 'wp-includes'   => [ 'type' => 'dir',  'recommended' => '0755' ],
        WP_CONTENT_DIR            => [ 'type' => 'dir',  'recommended' => '0755' ],
        ABSPATH . 'wp-config.php' => [ 'type' => 'file', 'recommended' => '0644' ],
        ABSPATH . '.htaccess'     => [ 'type' => 'file', 'recommended' => '0644' ],
    ];

    $nexura_all_secure = true;
    foreach ( $nexura_paths_to_check as $nexura_path => $nexura_info ) {
        if ( ! file_exists( $nexura_path ) ) { continue; }
        $nexura_perms   = substr( sprintf( '%o', fileperms( $nexura_path ) ), -4 );
        $nexura_is_safe = ( $nexura_info['type'] === 'dir' )
            ? in_array( $nexura_perms, [ '0755', '0750', '0700' ], true )
            : in_array( $nexura_perms, [ '0644', '0640', '0600', '0400' ], true );
        $nexura_is_acked = in_array( $nexura_path, $nexura_acknowledged, true );
        if ( ! $nexura_is_safe && ! $nexura_is_acked ) { $nexura_all_secure = false; }
    }
    ?>

    <?php if ( $nexura_all_secure ) : ?>
    <div style="background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.2);border-radius:8px;padding:12px 18px;margin:15px 0;display:flex;align-items:center;gap:10px;color:#10b981;font-size:13px;font-weight:500;">
        <svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
        <?php esc_html_e( 'All file permissions are secure!', 'nexura-security' ); ?>
    </div>
    <?php endif; ?>

    <table class="wp-list-table widefat striped" id="nexura-perm-table" style="margin-top:15px;">
        <thead>
            <tr>
                <th><?php esc_html_e( 'Path', 'nexura-security' ); ?></th>
                <th><?php esc_html_e( 'Current Permissions', 'nexura-security' ); ?></th>
                <th><?php esc_html_e( 'Recommended', 'nexura-security' ); ?></th>
                <th><?php esc_html_e( 'Status', 'nexura-security' ); ?></th>
                <th><?php esc_html_e( 'Action', 'nexura-security' ); ?></th>
            </tr>
        </thead>
        <tbody>
            <?php
            foreach ( $nexura_paths_to_check as $nexura_path => $nexura_info ) {
                if ( ! file_exists( $nexura_path ) ) { continue; }

                $nexura_perms    = substr( sprintf( '%o', fileperms( $nexura_path ) ), -4 );
                $nexura_is_safe  = ( $nexura_info['type'] === 'dir' )
                    ? in_array( $nexura_perms, [ '0755', '0750', '0700' ], true )
                    : in_array( $nexura_perms, [ '0644', '0640', '0600', '0400' ], true );
                $nexura_is_acked = in_array( $nexura_path, $nexura_acknowledged, true );
                $nexura_row_id   = 'nperm-' . md5( $nexura_path );
                $nexura_display  = str_replace( ABSPATH, '', $nexura_path ) ?: '/';
                // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
                $nexura_path_b64 = base64_encode( $nexura_path );
                ?>
                <tr id="<?php echo esc_attr( $nexura_row_id ); ?>">
                    <td><code><?php echo esc_html( $nexura_display ); ?></code></td>
                    <td class="nperm-current"><code><?php echo esc_html( $nexura_perms ); ?></code></td>
                    <td><code><?php echo esc_html( $nexura_info['recommended'] ); ?></code></td>
                    <td class="nperm-status">
                        <?php if ( $nexura_is_safe ) : ?>
                            <span style="color:#10b981;font-weight:bold;display:inline-flex;align-items:center;gap:4px;">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"></path></svg>
                                <?php esc_html_e( 'Secure', 'nexura-security' ); ?>
                            </span>
                        <?php elseif ( $nexura_is_acked ) : ?>
                            <span style="color:#10b981;font-weight:bold;display:inline-flex;align-items:center;gap:4px;">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"></path></svg>
                                <?php esc_html_e( 'Fixed', 'nexura-security' ); ?>
                            </span>
                        <?php else : ?>
                            <span style="color:#ef4444;font-weight:bold;display:inline-flex;align-items:center;gap:4px;">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
                                <?php esc_html_e( 'Insecure', 'nexura-security' ); ?>
                            </span>
                        <?php endif; ?>
                    </td>
                    <td class="nperm-action">
                        <?php if ( $nexura_is_safe ) : ?>
                            <span style="color:#64748b;font-size:12px;">&#8212;</span>
                        <?php elseif ( $nexura_is_acked ) : ?>
                            <button type="button"
                                class="nexura-reset-perm-btn button"
                                data-path="<?php echo esc_attr( $nexura_path_b64 ); ?>"
                                data-row="<?php echo esc_attr( $nexura_row_id ); ?>"
                                style="background:transparent;color:#64748b;border:1px solid #334155;border-radius:6px;padding:4px 10px;cursor:pointer;font-size:11px;">
                                <?php esc_html_e( 'Reset', 'nexura-security' ); ?>
                            </button>
                        <?php else : ?>
                            <button type="button"
                                class="nexura-fix-perm-btn button"
                                data-path="<?php echo esc_attr( $nexura_path_b64 ); ?>"
                                data-recommended="<?php echo esc_attr( $nexura_info['recommended'] ); ?>"
                                data-row="<?php echo esc_attr( $nexura_row_id ); ?>"
                                style="background:linear-gradient(135deg,#3b82f6,#6366f1);color:#fff;border:none;border-radius:6px;padding:5px 14px;cursor:pointer;font-size:12px;font-weight:600;display:inline-flex;align-items:center;gap:5px;line-height:1.6;">
                                <svg width="13" height="13" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                                <?php esc_html_e( 'Fix', 'nexura-security' ); ?>
                            </button>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php
            }
            ?>
        </tbody>
    </table>
    <p class="description" style="margin-top:15px;">
        <?php esc_html_e( 'Note: On Windows/XAMPP, clicking Fix applies chmod and marks the path as fixed so the status persists across reloads. On Linux hosting, the actual permissions are changed.', 'nexura-security' ); ?>
    </p>
</div>
