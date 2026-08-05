<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
?>
<form method="post" action="options.php">
    <?php settings_fields( 'NEXURA_settings_group' ); ?>
    <?php
    /**
     * Hook for Pro add-ons to inject UI at the top of the settings page.
     */
    do_action( 'nexura_settings_top' );
    ?>
    <div class="nexura-card nexura-fade-in">
        <h2><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path></svg></span> <?php esc_html_e( 'General Configuration', 'nexura-security' ); ?></h2>
        <table class="form-table">

            <tr>
                <th scope="row"><label for="NEXURA_google_api_key"><?php esc_html_e( 'Google Safe Browsing API Key', 'nexura-security' ); ?></label></th>
                <td>
                    <input type="text" id="NEXURA_google_api_key" name="NEXURA_google_api_key" value="<?php echo esc_attr( get_option( 'NEXURA_google_api_key' ) ); ?>" class="regular-text" />
                    <p class="description">
                        <?php esc_html_e( 'Enter your API key to enable Google Safe Browsing scans.', 'nexura-security' ); ?>
                        <br>
                        <a href="https://developers.google.com/safe-browsing/v4/get-started" target="_blank">
                            <?php esc_html_e( 'Click here for documentation on how to get your Google Safe Browsing API Key.', 'nexura-security' ); ?>
                        </a>
                    </p>
                  
                </td>
            </tr>
            <tr>
                <th scope="row"><label for="NEXURA_virustotal_api_key"><?php esc_html_e( 'VirusTotal API Key', 'nexura-security' ); ?></label></th>
                <td>
                    <input type="text" id="NEXURA_virustotal_api_key" name="NEXURA_virustotal_api_key" value="<?php echo esc_attr( get_option( 'NEXURA_virustotal_api_key' ) ); ?>" class="regular-text" />
                    <p class="description">
                        <?php esc_html_e( 'Enter your VirusTotal API key to enable Cloud Malware Scanning.', 'nexura-security' ); ?>
                        <br>
                        <a href="https://www.virustotal.com/gui/user/username/apikey" target="_blank">
                            <?php esc_html_e( 'Click here to get your free VirusTotal API Key.', 'nexura-security' ); ?>
                        </a>
                    </p>
                </td>
            </tr>
            
            <?php do_action('nexura_settings_pro_scheduled_scan'); ?>
            <tr>
                <th scope="row"><label for="NEXURA_custom_login_slug"><?php esc_html_e( 'Custom Login URL Slug', 'nexura-security' ); ?></label></th>
                <td>
                    <code><?php echo esc_url( site_url( '/' ) ); ?></code>
                    <input type="text" id="NEXURA_custom_login_slug" name="NEXURA_custom_login_slug" value="<?php echo esc_attr( get_option( 'NEXURA_custom_login_slug' ) ); ?>" class="regular-text" style="width: 150px;" placeholder="my-secret-login" />
                    <p class="description">
                        <?php esc_html_e( 'Change your WordPress login URL to prevent automated brute-force attacks.', 'nexura-security' ); ?><br>
                        <?php esc_html_e( 'Leave blank to use the default (wp-login.php).', 'nexura-security' ); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><label for="NEXURA_hide_third_party_notices"><?php esc_html_e( 'Hide Third-Party Notices', 'nexura-security' ); ?></label></th>
                <td>
                    <label class="nexura-switch">
                        <input type="checkbox" id="NEXURA_hide_third_party_notices" name="NEXURA_hide_third_party_notices" value="1" <?php checked( '1', get_option( 'NEXURA_hide_third_party_notices' ) ); ?> />
                        <span class="nexura-slider nexura-round"></span>
                    </label>
                    <p class="description">
                        <?php esc_html_e( 'Hide other plugins\' update and activation notices globally across the entire WordPress admin panel.', 'nexura-security' ); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><label for="NEXURA_enable_auto_heal"><?php esc_html_e( 'Auto-Heal (Crash Recovery)', 'nexura-security' ); ?></label></th>
                <td>
                    <label class="nexura-switch">
                        <input type="checkbox" id="NEXURA_enable_auto_heal" name="NEXURA_enable_auto_heal" value="1" <?php checked( '1', get_option( 'NEXURA_enable_auto_heal' ) ); ?> />
                        <span class="nexura-slider nexura-round"></span>
                    </label>
                    <p class="description">
                        <?php esc_html_e( 'Automatically detect and fix fatal errors (like broken plugins) in the background to keep your site online.', 'nexura-security' ); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><label for="NEXURA_enable_waf"><?php esc_html_e( 'Extended WAF & Core Auto-Restore', 'nexura-security' ); ?></label></th>
                <td>
                    <label class="nexura-switch">
                        <input type="checkbox" id="NEXURA_enable_waf" name="NEXURA_enable_waf" value="1" <?php checked( '1', get_option( 'NEXURA_enable_waf' ) ); ?> />
                        <span class="nexura-slider nexura-round"></span>
                    </label>
                    <p class="description">
                        <?php esc_html_e( 'Protects your site at the server level (.htaccess). Automatically restores missing WordPress core files if they are deleted by malware.', 'nexura-security' ); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><label for="NEXURA_enable_threat_intel"><?php esc_html_e( 'Global Threat Intelligence', 'nexura-security' ); ?></label></th>
                <td>
                    <label class="nexura-switch">
                        <input type="checkbox" id="NEXURA_enable_threat_intel" name="NEXURA_enable_threat_intel" value="1" <?php checked( '1', get_option( 'NEXURA_enable_threat_intel' ) ); ?> />
                        <span class="nexura-slider nexura-round"></span>
                    </label>
                    <p class="description">
                        <?php esc_html_e( 'Enable cloud-based threat intelligence to enhance your security. When enabled, the plugin will:', 'nexura-security' ); ?>
                    </p>
                    <ul style="list-style: disc; margin-left: 20px; color: var(--nexura-text-muted); font-size: 13px;">
                        <li><?php esc_html_e( 'Download malware signatures and blocklists from Nexura Cloud API', 'nexura-security' ); ?></li>
                        <li><?php esc_html_e( 'Sync known malicious IP addresses for automatic blocking', 'nexura-security' ); ?></li>
                        <li><?php esc_html_e( 'Fetch Cloudflare IP ranges for accurate visitor identification', 'nexura-security' ); ?></li>
                    </ul>
                    <p class="description" style="color: #eab308;">
                        <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="vertical-align: text-bottom;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg> <?php esc_html_e( 'This feature is disabled by default. No data is sent to or received from external servers until you enable it.', 'nexura-security' ); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Scan Scope', 'nexura-security' ); ?></th>
                <td>
                    <fieldset>
                        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
                            <label class="nexura-switch" style="margin: 0;">
                                <input type="checkbox" name="NEXURA_scan_core" value="1" <?php checked( get_option('NEXURA_scan_core', 1), 1 ); ?> />
                                <span class="nexura-slider"></span>
                            </label>
                            <span><?php esc_html_e( 'Scan WordPress Core Files', 'nexura-security' ); ?></span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
                            <label class="nexura-switch" style="margin: 0;">
                                <input type="checkbox" name="NEXURA_scan_plugins" value="1" <?php checked( get_option('NEXURA_scan_plugins', 1), 1 ); ?> />
                                <span class="nexura-slider"></span>
                            </label>
                            <span><?php esc_html_e( 'Scan Plugins', 'nexura-security' ); ?></span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
                            <label class="nexura-switch" style="margin: 0;">
                                <input type="checkbox" name="NEXURA_scan_themes" value="1" <?php checked( get_option('NEXURA_scan_themes', 1), 1 ); ?> />
                                <span class="nexura-slider"></span>
                            </label>
                            <span><?php esc_html_e( 'Scan Themes', 'nexura-security' ); ?></span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
                            <label class="nexura-switch" style="margin: 0;">
                                <input type="checkbox" name="NEXURA_scan_uploads" value="1" <?php checked( get_option('NEXURA_scan_uploads', 1), 1 ); ?> />
                                <span class="nexura-slider"></span>
                            </label>
                            <span><?php esc_html_e( 'Scan Uploads Directory', 'nexura-security' ); ?></span>
                        </div>
                        <?php do_action( 'nexura_settings_pro_scan_options' ); ?>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Pwned Password Check', 'nexura-security' ); ?></th>
                <td>
                    <fieldset>
                        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                            <label class="nexura-switch" style="margin: 0;">
                                <input type="checkbox" name="NEXURA_enable_pwned_check" value="1" <?php checked( get_option('NEXURA_enable_pwned_check', 0), 1 ); ?> />
                                <span class="nexura-slider"></span>
                            </label>
                            <span><?php esc_html_e( 'Check passwords against the Have I Been Pwned database (k-Anonymity API).', 'nexura-security' ); ?></span>
                        </div>
                        <p class="description">
                            <?php esc_html_e( 'If enabled, users will not be able to log in or set passwords that have been exposed in data breaches. Opt-in required.', 'nexura-security' ); ?>
                        </p>
                    </fieldset>
                </td>
            </tr>
            
            
            <!-- Geo-Blocking Section -->
            <?php do_action('nexura_settings_pro_geo_blocking'); ?>
            
            <!-- .htaccess Hardening Section -->
            <tr>
                <th scope="row"><?php esc_html_e( 'Hardening & .htaccess Rules', 'nexura-security' ); ?></th>
                <td>
                    <fieldset>
                        <p class="description" style="margin-bottom: 10px;">
                            <?php esc_html_e( 'These settings will automatically add protective rules to your server\'s .htaccess file.', 'nexura-security' ); ?>
                        </p>
                        
                        
                        
                        <?php $is_pro_locked = false; ?>
                        
                        <?php do_action( 'nexura_settings_pro_htaccess_options' ); ?>
                        
                        <div style="display: inline-block; vertical-align: top; width: 48%; margin-bottom: 20px; padding-right: 15px; box-sizing: border-box;">
                            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 4px;">
                                <label class="nexura-switch" style="margin: 0;">
                                    <input type="checkbox" name="NEXURA_htaccess_file" value="1" <?php checked( get_option('NEXURA_htaccess_file', 0), 1 ); ?> />
                                    <span class="nexura-slider"></span>
                                </label>
                                <strong><?php esc_html_e( 'Protect .htaccess', 'nexura-security' ); ?></strong>
                            </div>
                            <p class="description" style="margin-top: 0; margin-left: 52px;"><?php esc_html_e( 'Denies external access to the .htaccess file itself.', 'nexura-security' ); ?></p>
                        </div>
                        
                        <div style="display: inline-block; vertical-align: top; width: 48%; margin-bottom: 20px; box-sizing: border-box;">
                            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 4px;">
                                <label class="nexura-switch" style="margin: 0;">
                                    <input type="checkbox" name="NEXURA_htaccess_xmlrpc" value="1" <?php checked( get_option('NEXURA_htaccess_xmlrpc', 0), 1 ); ?> />
                                    <span class="nexura-slider"></span>
                                </label>
                                <strong><?php esc_html_e( 'Disable XML-RPC', 'nexura-security' ); ?></strong>
                            </div>
                            <p class="description" style="margin-top: 0; margin-left: 52px;"><?php esc_html_e( 'Blocks access to xmlrpc.php, which is frequently targeted by brute-force and amplification attacks.', 'nexura-security' ); ?></p>
                        </div>
                        
                        <div style="display: inline-block; vertical-align: top; width: 48%; margin-bottom: 20px; padding-right: 15px; box-sizing: border-box;">
                            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 4px;">
                                <label class="nexura-switch" style="margin: 0;">
                                    <input type="checkbox" name="NEXURA_htaccess_signature" value="1" <?php checked( get_option('NEXURA_htaccess_signature', 0), 1 ); ?> />
                                    <span class="nexura-slider"></span>
                                </label>
                                <strong><?php esc_html_e( 'Disable Server Signature', 'nexura-security' ); ?></strong>
                            </div>
                            <p class="description" style="margin-top: 0; margin-left: 52px;"><?php esc_html_e( 'Prevents the server from broadcasting its exact software version on error pages.', 'nexura-security' ); ?></p>
                        </div>
                        
                        <div style="display: inline-block; vertical-align: top; width: 48%; margin-bottom: 20px; box-sizing: border-box;">
                            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 4px;">
                                <label class="nexura-switch" style="margin: 0;">
                                    <input type="checkbox" name="NEXURA_htaccess_author" value="1" <?php checked( get_option('NEXURA_htaccess_author', 0), 1 ); ?> />
                                    <span class="nexura-slider"></span>
                                </label>
                                <strong><?php esc_html_e( 'Block Author Scans', 'nexura-security' ); ?></strong>
                            </div>
                            <p class="description" style="margin-top: 0; margin-left: 52px;"><?php esc_html_e( 'Prevents malicious bots from discovering user IDs via ?author=1 queries.', 'nexura-security' ); ?></p>
                        </div>
                        
                    </fieldset>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Database Backup', 'nexura-security' ); ?></th>
                <td>
                    <button type="button" id="nexura-db-backup-btn" class="button button-secondary">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 4px;"><ellipse cx="12" cy="5" rx="9" ry="3"></ellipse><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path></svg> 
                        <?php esc_html_e( 'Download Database Backup', 'nexura-security' ); ?>
                    </button>
                    <p class="description">
                        <?php esc_html_e( 'Download a complete backup of your WordPress database. This feature is completely free.', 'nexura-security' ); ?>
                    </p>
                    <div id="nexura-db-backup-status" style="margin-top: 10px; display: none;"></div>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Data Management', 'nexura-security' ); ?></th>
                <td>
                    <fieldset>
                        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                            <label class="nexura-switch" style="margin: 0;">
                                <input type="checkbox" name="NEXURA_delete_data_on_uninstall" value="1" <?php checked( get_option('NEXURA_delete_data_on_uninstall', 0), 1 ); ?> />
                                <span class="nexura-slider"></span>
                            </label>
                            <span><?php esc_html_e( 'Delete all data when the plugin is deleted', 'nexura-security' ); ?></span>
                        </div>
                        <p class="description">
                            <?php esc_html_e( 'If enabled, all scan results, activity logs, and settings will be permanently erased if you delete the plugin from the WordPress admin. Leave this disabled if you are updating the plugin by deleting and re-uploading.', 'nexura-security' ); ?>
                        </p>
                    </fieldset>
                </td>
            </tr>
        </table>
        <?php submit_button(); ?>
    </form>
</div>
