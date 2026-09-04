<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
?>
<form method="post" action="options.php">
    <?php if ( isset( $_GET['imported'] ) && $_GET['imported'] == 'true' ) : ?>
        <div class="notice notice-success is-dismissible" style="margin-left: 0;">
            <p><strong><?php esc_html_e( 'Settings imported successfully!', 'nexura-security' ); ?></strong></p>
        </div>
    <?php endif; ?>
    <?php settings_fields( 'NEXURA_settings_group' ); ?>
    <?php if ( function_exists( 'settings_errors' ) ) { settings_errors( 'NEXURA_settings_group' ); } ?>
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
                        <input type="hidden" name="NEXURA_hide_third_party_notices" value="0">
                                <input type="checkbox" id="NEXURA_hide_third_party_notices" name="NEXURA_hide_third_party_notices" value="1" <?php checked( '1', get_option( 'NEXURA_hide_third_party_notices' ) ); ?> />
                        <span class="nexura-slider nexura-round"></span>
                    </label>
                    <p class="description">
                        <?php esc_html_e( 'Hide other plugins\' update and activation notices globally across the entire WordPress admin panel.', 'nexura-security' ); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><label for="NEXURA_enable_magic_link"><?php esc_html_e( 'Enable Magic Link', 'nexura-security' ); ?></label></th>
                <td>
                    <label class="nexura-switch">
                        <input type="hidden" name="NEXURA_enable_magic_link" value="0">
                                <input type="checkbox" id="NEXURA_enable_magic_link" name="NEXURA_enable_magic_link" value="1" <?php checked( '1', get_option( 'NEXURA_enable_magic_link', '0' ) ); ?> />
                        <span class="nexura-slider nexura-round"></span>
                    </label>
                    <p class="description">
                        <?php esc_html_e( 'If enabled, users can log in via an email link without needing a password. The button will appear on the default WordPress login page.', 'nexura-security' ); ?>
                    </p>
                    <p class="description" style="color: #f59e0b; margin-top: 6px;">
                        <strong><?php esc_html_e( '⚠ Security Note:', 'nexura-security' ); ?></strong>
                        <?php esc_html_e( 'Magic Link provides passwordless login. Ensure your users\' email accounts are secure before enabling. Rate limiting is applied per IP and per account (3 requests / 15 min).', 'nexura-security' ); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><label for="NEXURA_enable_auto_heal"><?php esc_html_e( 'Auto-Heal (Crash Recovery)', 'nexura-security' ); ?></label></th>
                <td>
                    <label class="nexura-switch">
                        <input type="hidden" name="NEXURA_enable_auto_heal" value="0">
                                <input type="checkbox" id="NEXURA_enable_auto_heal" name="NEXURA_enable_auto_heal" value="1" <?php checked( '1', get_option( 'NEXURA_enable_auto_heal' ) ); ?> />
                        <span class="nexura-slider nexura-round"></span>
                    </label>
                    <p class="description">
                        <?php esc_html_e( 'Automatically detect and fix fatal errors (like broken plugins) in the background to keep your site online.', 'nexura-security' ); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><label for="NEXURA_enable_waf"><?php esc_html_e( 'WAF Operating Mode', 'nexura-security' ); ?></label></th>
                <td>
                    <?php
                    $waf_mode = get_option( 'NEXURA_enable_waf', 'protecting' );
                    if ( $waf_mode === '1' || $waf_mode === 1 || $waf_mode === true ) $waf_mode = 'protecting';
                    if ( $waf_mode === '0' || $waf_mode === 0 || $waf_mode === false ) $waf_mode = 'disabled';
                    ?>
                    <select id="NEXURA_enable_waf" name="NEXURA_enable_waf" style="padding: 8px; border-radius: 6px; border: 1px solid var(--nexura-border); background: var(--nexura-bg-secondary); color: var(--nexura-text); min-width: 250px;">
                        <option value="disabled" <?php selected( $waf_mode, 'disabled' ); ?>><?php esc_html_e( 'Disabled', 'nexura-security' ); ?></option>
                        <option value="learning" <?php selected( $waf_mode, 'learning' ); ?>><?php esc_html_e( 'Learning Mode (Log Only)', 'nexura-security' ); ?></option>
                        <option value="protecting" <?php selected( $waf_mode, 'protecting' ); ?>><?php esc_html_e( 'Protecting (Block Threats)', 'nexura-security' ); ?></option>
                    </select>
                    <p class="description">
                        <?php esc_html_e( 'Learning Mode observes and logs malicious traffic without blocking it, useful for avoiding false positives on new sites.', 'nexura-security' ); ?>
                    </p>
                    
                    <div style="margin-top: 15px; padding: 12px; background: rgba(59, 130, 246, 0.1); border-left: 3px solid #3b82f6; border-radius: 4px;">
                        <h4 style="margin: 0 0 5px 0; color: #3b82f6; font-size: 13px;">🛡️ Data Privacy for Nginx Users</h4>
                        <p style="margin: 0; font-size: 12px; color: var(--nexura-text-muted);">
                            If you are using Nginx, you must manually block public access to WAF logs. Add this to your server configuration:
                            <code style="display: block; margin-top: 5px; background: rgba(0,0,0,0.2); padding: 5px; border-radius: 4px;">location ~* ^/wp-content/uploads/nexura-(security|logs)/.*\.(json|log|txt|mmdb|sql|zip)$ { deny all; }</code>
                        </p>
                    </div>
                </td>
            </tr>
            <tr>
                <th scope="row"><label for="NEXURA_enable_advanced_fs"><?php esc_html_e( 'Advanced Filesystem Operations', 'nexura-security' ); ?></label></th>
                <td>
                    <label class="nexura-switch">
                        <input type="hidden" name="NEXURA_enable_advanced_fs" value="0">
                                <input type="checkbox" id="NEXURA_enable_advanced_fs" name="NEXURA_enable_advanced_fs" value="1" <?php checked( '1', get_option( 'NEXURA_enable_advanced_fs' ) ); ?> />
                        <span class="nexura-slider nexura-round"></span>
                    </label>
                    <p class="description">
                        <?php esc_html_e( 'Enable advanced operations like chattr (+i / -i) to prevent malware from regenerating dummy files. Warning: High risk capability.', 'nexura-security' ); ?>
                    </p>
                    <p class="description" style="color: #f59e0b; margin-top: 6px;">
                        <strong><?php esc_html_e( '⚠ System Warning:', 'nexura-security' ); ?></strong>
                        <?php esc_html_e( 'Advanced filesystem operations use shell_exec() and may not be supported on all hosting environments.', 'nexura-security' ); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><label for="NEXURA_enable_threat_intel"><?php esc_html_e( 'Global Threat Intelligence', 'nexura-security' ); ?></label></th>
                <td>
                    <label class="nexura-switch">
                        <input type="hidden" name="NEXURA_enable_threat_intel" value="0">
                        <input type="checkbox" name="NEXURA_enable_threat_intel" id="NEXURA_enable_threat_intel" value="1" <?php checked( get_option('NEXURA_enable_threat_intel', 0), 1 ); ?> />
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
                                <input type="hidden" name="NEXURA_scan_core" value="0">
                                <input type="checkbox" name="NEXURA_scan_core" value="1" <?php checked( get_option('NEXURA_scan_core', 1), 1 ); ?> />
                                <span class="nexura-slider"></span>
                            </label>
                            <span><?php esc_html_e( 'Scan WordPress Core Files', 'nexura-security' ); ?></span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
                            <label class="nexura-switch" style="margin: 0;">
                                <input type="hidden" name="NEXURA_scan_plugins" value="0">
                                <input type="checkbox" name="NEXURA_scan_plugins" value="1" <?php checked( get_option('NEXURA_scan_plugins', 1), 1 ); ?> />
                                <span class="nexura-slider"></span>
                            </label>
                            <span><?php esc_html_e( 'Scan Plugins', 'nexura-security' ); ?></span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
                            <label class="nexura-switch" style="margin: 0;">
                                <input type="hidden" name="NEXURA_enable_smart_scan" value="0">
                                <input type="checkbox" name="NEXURA_enable_smart_scan" value="1" <?php checked( get_option('NEXURA_enable_smart_scan', 1), 1 ); ?> />
                                <span class="nexura-slider"></span>
                            </label>
                            <span>
                                <?php esc_html_e( 'Enable Smart Scan (Delta)', 'nexura-security' ); ?>
                                <br><small style="color: var(--nexura-text-muted);"><?php esc_html_e( 'After the first full scan, only scan files that have been modified (Saves up to 90% CPU usage).', 'nexura-security' ); ?></small>
                            </span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
                            <label class="nexura-switch" style="margin: 0;">
                                <input type="hidden" name="NEXURA_scan_themes" value="0">
                                <input type="checkbox" name="NEXURA_scan_themes" value="1" <?php checked( get_option('NEXURA_scan_themes', 1), 1 ); ?> />
                                <span class="nexura-slider"></span>
                            </label>
                            <span><?php esc_html_e( 'Scan Themes', 'nexura-security' ); ?></span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
                            <label class="nexura-switch" style="margin: 0;">
                                <input type="hidden" name="NEXURA_scan_uploads" value="0">
                                <input type="checkbox" name="NEXURA_scan_uploads" value="1" <?php checked( get_option('NEXURA_scan_uploads', 1), 1 ); ?> />
                                <span class="nexura-slider"></span>
                            </label>
                            <span><?php esc_html_e( 'Scan Uploads Directory', 'nexura-security' ); ?></span>
                        </div>
                        <?php do_action( 'nexura_settings_pro_scan_options' ); ?>
                    </fieldset>
                </td>
            </tr>
            
            <tr>
                <th scope="row"><?php esc_html_e( 'Log Retention Policy', 'nexura-security' ); ?></th>
                <td>
                    <fieldset>
                        <select name="NEXURA_log_retention" id="NEXURA_log_retention" style="width: 200px; background: rgba(30, 41, 59, 0.7); border: 1px solid var(--nexura-border); color: #f8fafc; border-radius: 4px; padding: 4px 8px;">
                            <option value="7" <?php selected( get_option('NEXURA_log_retention', 30), 7 ); ?>>7 Days</option>
                            <option value="30" <?php selected( get_option('NEXURA_log_retention', 30), 30 ); ?>>30 Days (Default)</option>
                            <option value="90" <?php selected( get_option('NEXURA_log_retention', 30), 90 ); ?>>90 Days</option>
                            <option value="180" <?php selected( get_option('NEXURA_log_retention', 30), 180 ); ?>>180 Days</option>
                            <option value="365" <?php selected( get_option('NEXURA_log_retention', 30), 365 ); ?>>1 Year</option>
                            <option value="0" <?php selected( get_option('NEXURA_log_retention', 30), 0 ); ?>>Forever</option>
                        </select>
                        <p class="description">
                            <?php esc_html_e( 'Automatically delete old security logs (Attack, Audit, Visitor, reCAPTCHA) after this period. Keeps your database small.', 'nexura-security' ); ?>
                        </p>
                    </fieldset>
                </td>
            </tr>

            <!-- Visitor Monitoring & Privacy Section -->
            <tr>
                <th scope="row"><label for="NEXURA_enable_visitor_tracking"><?php esc_html_e( 'Visitor Monitoring', 'nexura-security' ); ?></label></th>
                <td>
                    <div style="background: rgba(30, 41, 59, 0.4); border: 1px solid var(--nexura-border); padding: 15px; border-radius: 6px;">
                        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px;">
                            <strong><?php esc_html_e( 'Enable Visitor Monitoring', 'nexura-security' ); ?></strong>
                            <label class="nexura-switch" style="margin: 0;">
                                <input type="hidden" name="NEXURA_enable_visitor_tracking" value="0">
                                <input type="checkbox" id="NEXURA_enable_visitor_tracking" name="NEXURA_enable_visitor_tracking" value="1" <?php checked( '1', get_option( 'NEXURA_enable_visitor_tracking', '0' ) ); ?> />
                                <span class="nexura-slider nexura-round"></span>
                            </label>
                        </div>
                        <p class="description" style="color: #38bdf8; margin: 0 0 12px 0; font-size: 13px; line-height: 1.5;">
                            <strong><?php esc_html_e( 'ℹ Privacy & Legal Consent Notice:', 'nexura-security' ); ?></strong>
                            <?php esc_html_e( 'This feature collects visitor information such as IP address, browser, and page views. Enable only if you have the required privacy/legal consent.', 'nexura-security' ); ?>
                        </p>
                        
                        <div style="border-top: 1px solid rgba(255,255,255,0.08); padding-top: 12px; margin-top: 12px;">
                            <p style="margin: 0 0 8px 0; font-weight: 600; font-size: 13px; color: #f8fafc;"><?php esc_html_e( 'Data Collection Controls:', 'nexura-security' ); ?></p>
                            <fieldset style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px;">
                                <label style="display: flex; align-items: center; gap: 8px; font-size: 13px;">
                                    <input type="hidden" name="NEXURA_vt_collect_ip" value="0">
                                    <input type="checkbox" name="NEXURA_vt_collect_ip" value="1" <?php checked( '1', get_option( 'NEXURA_vt_collect_ip', '1' ) ); ?> />
                                    <span><?php esc_html_e( 'IP Address', 'nexura-security' ); ?></span>
                                </label>
                                <label style="display: flex; align-items: center; gap: 8px; font-size: 13px;">
                                    <input type="hidden" name="NEXURA_vt_collect_user_id" value="0">
                                    <input type="checkbox" name="NEXURA_vt_collect_user_id" value="1" <?php checked( '1', get_option( 'NEXURA_vt_collect_user_id', '1' ) ); ?> />
                                    <span><?php esc_html_e( 'User ID', 'nexura-security' ); ?></span>
                                </label>
                                <label style="display: flex; align-items: center; gap: 8px; font-size: 13px;">
                                    <input type="hidden" name="NEXURA_vt_collect_referrer" value="0">
                                    <input type="checkbox" name="NEXURA_vt_collect_referrer" value="1" <?php checked( '1', get_option( 'NEXURA_vt_collect_referrer', '1' ) ); ?> />
                                    <span><?php esc_html_e( 'Referrer URL', 'nexura-security' ); ?></span>
                                </label>
                                <label style="display: flex; align-items: center; gap: 8px; font-size: 13px;">
                                    <input type="hidden" name="NEXURA_vt_collect_ua" value="0">
                                    <input type="checkbox" name="NEXURA_vt_collect_ua" value="1" <?php checked( '1', get_option( 'NEXURA_vt_collect_ua', '1' ) ); ?> />
                                    <span><?php esc_html_e( 'User Agent / Browser', 'nexura-security' ); ?></span>
                                </label>
                            </fieldset>
                        </div>
                    </div>
                </td>
            </tr>
            <!-- WooCommerce Security Section -->
            <?php if ( class_exists( 'WooCommerce' ) ) : ?>
            <tr>
                <th scope="row">
                    <h3 style="margin: 0; font-size: 14px; color: #3b82f6; display: flex; align-items: center; gap: 8px;">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 2L3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4z"></path><line x1="3" y1="6" x2="21" y2="6"></line><path d="M16 10a4 4 0 0 1-8 0"></path></svg>
                        <?php esc_html_e( 'WooCommerce Security', 'nexura-security' ); ?>
                    </h3>
                </th>
                <td>
                    <div style="background: rgba(30, 41, 59, 0.4); border: 1px solid var(--nexura-border); padding: 15px; border-radius: 6px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; padding-bottom: 15px; border-bottom: 1px solid rgba(255,255,255,0.05);">
                            <div>
                                <strong><?php esc_html_e( 'Master Protection', 'nexura-security' ); ?></strong>
                                <p class="description" style="margin: 2px 0 0 0;"><?php esc_html_e( 'Enable enterprise-grade security for your store.', 'nexura-security' ); ?></p>
                            </div>
                            <label class="nexura-switch">
                                <input type="hidden" name="NEXURA_wc_security_master" value="0">
                                <input type="checkbox" id="NEXURA_wc_security_master" name="NEXURA_wc_security_master" value="1" <?php checked( '1', get_option( 'NEXURA_wc_security_master', '0' ) ); ?> />
                                <span class="nexura-slider nexura-round"></span>
                            </label>
                        </div>

                        <div id="nexura-wc-settings-wrapper" style="opacity: <?php echo get_option( 'NEXURA_wc_security_master', '0' ) === '1' ? '1' : '0.5'; ?>; pointer-events: <?php echo get_option( 'NEXURA_wc_security_master', '0' ) === '1' ? 'auto' : 'none'; ?>; transition: all 0.3s ease;">
                            <div style="margin-bottom: 20px;">
                                <label for="NEXURA_wc_security_level" style="font-weight: 600; display: block; margin-bottom: 8px;"><?php esc_html_e( 'Security Level', 'nexura-security' ); ?></label>
                                <select name="NEXURA_wc_security_level" id="NEXURA_wc_security_level" style="width: 100%; max-width: 300px; background: rgba(15, 23, 42, 0.7); border: 1px solid var(--nexura-border); color: #f8fafc; border-radius: 4px; padding: 4px 8px;">
                                    <option value="basic" <?php selected( get_option('NEXURA_wc_security_level', 'balanced'), 'basic' ); ?>><?php esc_html_e( 'Basic (Low Impact)', 'nexura-security' ); ?></option>
                                    <option value="balanced" <?php selected( get_option('NEXURA_wc_security_level', 'balanced'), 'balanced' ); ?>><?php esc_html_e( 'Balanced (Recommended)', 'nexura-security' ); ?></option>
                                    <option value="strict" <?php selected( get_option('NEXURA_wc_security_level', 'balanced'), 'strict' ); ?>><?php esc_html_e( 'Strict (Aggressive)', 'nexura-security' ); ?></option>
                                    <option value="custom" <?php selected( get_option('NEXURA_wc_security_level', 'balanced'), 'custom' ); ?>><?php esc_html_e( 'Custom (Manual Control)', 'nexura-security' ); ?></option>
                                </select>
                            </div>

                            <fieldset id="nexura-wc-modules">
                                <legend class="screen-reader-text"><span><?php esc_html_e( 'Protection Modules', 'nexura-security' ); ?></span></legend>
                                <strong style="display:block; margin-bottom: 10px;"><?php esc_html_e( 'Protection Modules', 'nexura-security' ); ?></strong>
                                
                                <?php
                                $modules = [
                                    'NEXURA_wc_login_abuse' => __( 'Login Abuse Protection', 'nexura-security' ),
                                    'NEXURA_wc_fake_registration' => __( 'Fake Registration Protection', 'nexura-security' ),
                                    'NEXURA_wc_checkout_abuse' => __( 'Checkout Abuse Protection', 'nexura-security' ),
                                    'NEXURA_wc_cart_abuse' => __( 'Cart Abuse Protection', 'nexura-security' ),
                                    'NEXURA_wc_coupon_abuse' => __( 'Coupon Abuse Protection', 'nexura-security' ),
                                    'NEXURA_wc_rest_api' => __( 'REST API Protection', 'nexura-security' ),
                                    'NEXURA_wc_order_api' => __( 'Order API Protection', 'nexura-security' ),
                                    'NEXURA_wc_xmlrpc' => __( 'XML-RPC Protection', 'nexura-security' ),
                                    'NEXURA_wc_admin_ajax' => __( 'Admin AJAX Protection', 'nexura-security' ),
                                    'NEXURA_wc_payment_protection' => __( 'Payment Endpoint Protection', 'nexura-security' ),
                                ];

                                foreach ( $modules as $key => $label ) {
                                    $checked = get_option( $key, '1' ); // Default 1 for balanced
                                    ?>
                                    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                                        <label class="nexura-switch" style="margin: 0; transform: scale(0.8); transform-origin: left center;">
                                            <input type="hidden" name="<?php echo esc_attr( $key ); ?>" value="0">
                                            <input type="checkbox" name="<?php echo esc_attr( $key ); ?>" class="nexura-wc-module-toggle" value="1" <?php checked( $checked, '1' ); ?> />
                                            <span class="nexura-slider nexura-round"></span>
                                        </label>
                                        <span style="font-size: 13px;"><?php echo esc_html( $label ); ?></span>
                                    </div>
                                    <?php
                                }
                                ?>
                            </fieldset>
                        </div>
                    </div>
                    <script>
                        document.addEventListener('DOMContentLoaded', function() {
                            const master = document.getElementById('NEXURA_wc_security_master');
                            const wrapper = document.getElementById('nexura-wc-settings-wrapper');
                            const levelSelect = document.getElementById('NEXURA_wc_security_level');
                            const toggles = document.querySelectorAll('.nexura-wc-module-toggle');
                            
                            master.addEventListener('change', function() {
                                if(this.checked) {
                                    wrapper.style.opacity = '1';
                                    wrapper.style.pointerEvents = 'auto';
                                } else {
                                    wrapper.style.opacity = '0.5';
                                    wrapper.style.pointerEvents = 'none';
                                }
                            });

                            const applyPreset = function() {
                                const level = levelSelect.value;
                                if (level === 'custom') return; // User manually controls

                                toggles.forEach(toggle => {
                                    if (level === 'basic') {
                                        // Basic: Login, Registration, XML-RPC
                                        if (['NEXURA_wc_login_abuse', 'NEXURA_wc_fake_registration', 'NEXURA_wc_xmlrpc'].includes(toggle.name)) {
                                            toggle.checked = true;
                                        } else {
                                            toggle.checked = false;
                                        }
                                    } else if (level === 'balanced' || level === 'strict') {
                                        // Balanced/Strict: Enable everything by default
                                        toggle.checked = true;
                                    }
                                });
                            };

                            levelSelect.addEventListener('change', applyPreset);
                            
                            // If user manually clicks a toggle, switch level to custom
                            toggles.forEach(toggle => {
                                toggle.addEventListener('change', function() {
                                    levelSelect.value = 'custom';
                                });
                            });
                        });
                    </script>
                </td>
            </tr>
            <?php endif; ?>
                </td>
            </tr>

            <tr>
                <th scope="row"><?php esc_html_e( 'Pwned Password Check', 'nexura-security' ); ?></th>
                <td>
                    <fieldset>
                        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                            <label class="nexura-switch" style="margin: 0;">
                                <input type="hidden" name="NEXURA_enable_pwned_check" value="0">
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
            
            <!-- Geo-Blocking Section (Pro Upsell) -->
            <?php if ( ! nexura_is_pro() ) : ?>
            <tr>
                <th scope="row"><?php esc_html_e( 'Geo-Blocking (Blocked Countries)', 'nexura-security' ); ?> <svg width="15" height="15" viewBox="0 0 24 24" fill="#ec4899" xmlns="http://www.w3.org/2000/svg" style="vertical-align:-2px;"><path d="M12 17.27L18.18 21l-1.64-7.03L22 9.24l-7.19-.61L12 2 9.19 8.63 2 9.24l5.46 4.73L5.82 21z"/></svg></th>
                <td>
                    <div style="position: relative; overflow: hidden; background: rgba(15, 23, 42, 0.4); border: 1px solid var(--nexura-border); border-radius: 6px; padding: 15px; min-height: 170px;">
                        <!-- Blur Overlay -->
                        <div style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; backdrop-filter: blur(4px); background: rgba(15, 23, 42, 0.6); display: flex; flex-direction: column; align-items: center; justify-content: center; z-index: 10;">
                            <h4 style="color: #f3f4f6; margin: 0 0 10px 0; font-size: 16px; display: flex; align-items: center; gap: 8px;">
                                <span style="color:#ec4899;">👑</span> Pro Feature
                            </h4>
                            <p style="color: #94a3b8; font-size: 13px; text-align: center; max-width: 300px; margin: 0 0 15px 0;">
                                <?php esc_html_e( 'Upgrade to Nexura Pro to access the dedicated Geo-Blocking Dashboard and block malicious traffic from 250+ countries at the firewall level.', 'nexura-security' ); ?>
                            </p>
                            <a href="<?php echo esc_url( admin_url( 'admin.php?page=nexura-about' ) ); ?>" class="button button-primary" style="background: #ec4899; border-color: #ec4899; box-shadow: 0 2px 10px rgba(236, 72, 153, 0.3);">
                                <?php esc_html_e( 'Learn More', 'nexura-security' ); ?>
                            </a>
                        </div>
                        
                        <!-- Fake Background Content -->
                        <div style="opacity: 0.4; filter: blur(2px); pointer-events: none; user-select: none;">
                            <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 10px;">
                                <?php 
                                $fake_countries = ['Russia (RU)', 'China (CN)', 'North Korea (KP)', 'Iran (IR)', 'Syria (SY)', 'Brazil (BR)'];
                                foreach($fake_countries as $fake_c) : ?>
                                <div style="display: flex; align-items: center; gap: 8px; background: rgba(255,255,255,0.05); padding: 6px 10px; border-radius: 4px;">
                                    <label class="nexura-switch" style="margin: 0; transform: scale(0.8);">
                                        <input type="checkbox" disabled />
                                        <span class="nexura-slider"></span>
                                    </label>
                                    <span style="font-size: 13px;"><?php echo esc_html($fake_c); ?></span>
                                </div>
                                <?php endforeach; ?>
                            </div>
                        </div>
                    </div>
                </td>
            </tr>
            <?php endif; ?>
            <!-- Alert Notifications Section -->
            <tr>
                <th scope="row"><?php esc_html_e( 'Alert Notifications', 'nexura-security' ); ?></th>
                <td>
                    <fieldset>
                        <p class="description" style="margin-bottom: 12px;">
                            <?php esc_html_e( 'Get instant notifications when security events occur on your site.', 'nexura-security' ); ?>
                        </p>
                        
                        <!-- Email Alert Toggle -->
                        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
                            <label class="nexura-switch" style="margin: 0;">
                                <input type="hidden" name="NEXURA_enable_email_alerts" value="0">
                                <input type="checkbox" id="NEXURA_enable_email_alerts" name="NEXURA_enable_email_alerts" value="1" <?php checked( '1', get_option( 'NEXURA_enable_email_alerts' ) ); ?> />
                                <span class="nexura-slider nexura-round"></span>
                            </label>
                            <span><?php esc_html_e( 'Enable Email Alerts', 'nexura-security' ); ?></span>
                        </div>
                        <div style="margin-left: 0; margin-bottom: 16px;">
                            <input type="text" id="NEXURA_alert_email_address" name="NEXURA_alert_email_address" value="<?php echo esc_attr( get_option( 'NEXURA_alert_email_address' ) ); ?>" class="regular-text" placeholder="<?php echo esc_attr( get_option( 'admin_email' ) ); ?>" />
                            <p class="description"><?php esc_html_e( 'Enter email addresses (comma-separated for multiple). Leave blank to use the default WordPress admin email.', 'nexura-security' ); ?></p>
                        </div>
                        
                        <div style="margin-left: 15px; margin-bottom: 16px; border-left: 2px solid var(--nexura-border); padding-left: 15px;">
                            <p style="font-weight: 600; margin-bottom: 10px;"><?php esc_html_e( 'Alert Severities:', 'nexura-security' ); ?></p>
                            
                            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                                <label class="nexura-switch" style="margin: 0; transform: scale(0.8);">
                                    <input type="hidden" name="NEXURA_email_alerts_critical" value="0">
                                <input type="checkbox" name="NEXURA_email_alerts_critical" value="1" <?php checked( '1', get_option( 'NEXURA_email_alerts_critical', '1' ) ); ?> />
                                    <span class="nexura-slider nexura-round"></span>
                                </label>
                                <span style="font-size: 13px; color: #ef4444; font-weight: bold;"><?php esc_html_e( 'Critical Events', 'nexura-security' ); ?></span>
                            </div>

                            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                                <label class="nexura-switch" style="margin: 0; transform: scale(0.8);">
                                    <input type="hidden" name="NEXURA_email_alerts_high" value="0">
                                <input type="checkbox" name="NEXURA_email_alerts_high" value="1" <?php checked( '1', get_option( 'NEXURA_email_alerts_high', '1' ) ); ?> />
                                    <span class="nexura-slider nexura-round"></span>
                                </label>
                                <span style="font-size: 13px; color: #f59e0b; font-weight: bold;"><?php esc_html_e( 'High Events', 'nexura-security' ); ?></span>
                            </div>

                            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                                <label class="nexura-switch" style="margin: 0; transform: scale(0.8);">
                                    <input type="hidden" name="NEXURA_email_alerts_medium" value="0">
                                <input type="checkbox" name="NEXURA_email_alerts_medium" value="1" <?php checked( '1', get_option( 'NEXURA_email_alerts_medium', '0' ) ); ?> />
                                    <span class="nexura-slider nexura-round"></span>
                                </label>
                                <span style="font-size: 13px; color: #3b82f6; font-weight: bold;"><?php esc_html_e( 'Medium Events', 'nexura-security' ); ?></span>
                            </div>
                        </div>
                        
                        <!-- Webhook Alert Toggle -->
                        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
                            <label class="nexura-switch" style="margin: 0;">
                                <input type="hidden" name="NEXURA_enable_webhook_alerts" value="0">
                                <input type="checkbox" id="NEXURA_enable_webhook_alerts" name="NEXURA_enable_webhook_alerts" value="1" <?php checked( '1', get_option( 'NEXURA_enable_webhook_alerts' ) ); ?> />
                                <span class="nexura-slider nexura-round"></span>
                            </label>
                            <span><?php esc_html_e( 'Enable Webhook Alerts (Slack / Discord)', 'nexura-security' ); ?></span>
                        </div>
                        <div style="margin-left: 0; margin-bottom: 8px;">
                            <input type="text" id="NEXURA_webhook_url" name="NEXURA_webhook_url" value="<?php echo esc_attr( get_option( 'NEXURA_webhook_url' ) ); ?>" class="regular-text" placeholder="https://discord.com/api/webhooks/..." />
                            <p class="description">
                                <?php esc_html_e( 'Enter your Slack or Discord Incoming Webhook URL. Alerts will be sent as formatted messages.', 'nexura-security' ); ?>
                            </p>
                        </div>
                    </fieldset>
                </td>
            </tr>
            
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
                                    <input type="hidden" name="NEXURA_htaccess_file" value="0">
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
                                    <input type="hidden" name="NEXURA_htaccess_xmlrpc" value="0">
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
                                    <input type="hidden" name="NEXURA_htaccess_signature" value="0">
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
                                    <input type="hidden" name="NEXURA_htaccess_author" value="0">
                                    <input type="checkbox" name="NEXURA_htaccess_author" value="1" <?php checked( get_option('NEXURA_htaccess_author', 0), 1 ); ?> />
                                    <span class="nexura-slider"></span>
                                </label>
                                <strong><?php esc_html_e( 'Disable Author Enumeration', 'nexura-security' ); ?></strong>
                            </div>
                            <p class="description" style="margin-top: 0; margin-left: 52px;"><?php esc_html_e( 'Prevents hackers from scraping your usernames via /?author=1 requests.', 'nexura-security' ); ?></p>
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
                                <input type="hidden" name="NEXURA_delete_data_on_uninstall" value="0">
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
            <tr>
                <th scope="row"><?php esc_html_e( 'Privacy & External Services', 'nexura-security' ); ?></th>
                <td>
                    <p class="description" style="margin-top: 0; margin-bottom: 16px;">
                        <?php esc_html_e( 'In compliance with WordPress.org Guidelines, below is a complete disclosure of third-party external services used by Nexura Security. You can enable or disable each integration and inspect transmitted data.', 'nexura-security' ); ?>
                    </p>

                    <div class="nexura-privacy-disclosures" style="display: flex; flex-direction: column; gap: 12px;">
                        <!-- 1. Nexura Threat Intelligence -->
                        <div style="background: rgba(15, 23, 42, 0.6); padding: 14px 18px; border-radius: 10px; border: 1px solid var(--nexura-border);">
                            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
                                <strong style="color: #f8fafc; font-size: 14px;"><?php esc_html_e( 'Nexura Threat Intelligence', 'nexura-security' ); ?></strong>
                                <label class="nexura-switch" style="margin: 0;">
                                    <input type="hidden" name="NEXURA_enable_threat_intel" value="0">
                                    <input type="checkbox" name="NEXURA_enable_threat_intel" id="NEXURA_enable_threat_intel" value="1" <?php checked( get_option('NEXURA_enable_threat_intel', 1), 1 ); ?> />
                                    <span class="nexura-slider"></span>
                                </label>
                            </div>
                            <div style="font-size: 12px; color: #94a3b8; line-height: 1.6;">
                                <div><strong>Data Sent:</strong> File SHA-256 hashes, anonymized IP threat scores</div>
                                <div><strong>Purpose:</strong> Real-time zero-day malware signatures & IP reputation feeds</div>
                                <div><strong>Trigger:</strong> Automated background scans or WAF IP lookup</div>
                                <div><strong>Provider:</strong> Sentinel Guard Security / Nexura Cloud | <a href="https://nexurasecurity.com/privacy" target="_blank" style="color: #38bdf8;">Privacy Policy</a></div>
                            </div>
                        </div>

                        <!-- 2. Cloudflare Turnstile -->
                        <div style="background: rgba(15, 23, 42, 0.6); padding: 14px 18px; border-radius: 10px; border: 1px solid var(--nexura-border);">
                            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
                                <strong style="color: #f8fafc; font-size: 14px;"><?php esc_html_e( 'Cloudflare Turnstile', 'nexura-security' ); ?></strong>
                                <label class="nexura-switch" style="margin: 0;">
                                    <input type="hidden" name="NEXURA_enable_turnstile" value="0">
                                    <input type="checkbox" name="NEXURA_enable_turnstile" id="NEXURA_enable_turnstile" value="1" <?php checked( get_option('NEXURA_enable_turnstile', 0), 1 ); ?> />
                                    <span class="nexura-slider"></span>
                                </label>
                            </div>
                            <div style="font-size: 12px; color: #94a3b8; line-height: 1.6;">
                                <div><strong>Data Sent:</strong> Turnstile visitor response token, IP address, User Agent</div>
                                <div><strong>Purpose:</strong> Privacy-friendly bot validation on login, registration, and comment forms</div>
                                <div><strong>Trigger:</strong> Form submission by site visitors when Turnstile is enabled</div>
                                <div><strong>Provider:</strong> Cloudflare, Inc. | <a href="https://www.cloudflare.com/privacypolicy/" target="_blank" style="color: #38bdf8;">Privacy Policy</a></div>
                            </div>
                        </div>

                        <!-- 3. Google reCAPTCHA -->
                        <div style="background: rgba(15, 23, 42, 0.6); padding: 14px 18px; border-radius: 10px; border: 1px solid var(--nexura-border);">
                            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
                                <strong style="color: #f8fafc; font-size: 14px;"><?php esc_html_e( 'Google reCAPTCHA', 'nexura-security' ); ?></strong>
                                <label class="nexura-switch" style="margin: 0;">
                                    <input type="hidden" name="NEXURA_enable_recaptcha" value="0">
                                    <input type="checkbox" name="NEXURA_enable_recaptcha" id="NEXURA_enable_recaptcha" value="1" <?php checked( get_option('NEXURA_enable_recaptcha', 0), 1 ); ?> />
                                    <span class="nexura-slider"></span>
                                </label>
                            </div>
                            <div style="font-size: 12px; color: #94a3b8; line-height: 1.6;">
                                <div><strong>Data Sent:</strong> reCAPTCHA response token, IP address, browser environment details</div>
                                <div><strong>Purpose:</strong> Automated brute-force and spam bot mitigation</div>
                                <div><strong>Trigger:</strong> Login or form submit when reCAPTCHA v2/v3 is enabled</div>
                                <div><strong>Provider:</strong> Google LLC | <a href="https://policies.google.com/privacy" target="_blank" style="color: #38bdf8;">Privacy Policy</a></div>
                            </div>
                        </div>

                        <!-- 4. Google Safe Browsing -->
                        <div style="background: rgba(15, 23, 42, 0.6); padding: 14px 18px; border-radius: 10px; border: 1px solid var(--nexura-border);">
                            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
                                <strong style="color: #f8fafc; font-size: 14px;"><?php esc_html_e( 'Google Safe Browsing', 'nexura-security' ); ?></strong>
                                <label class="nexura-switch" style="margin: 0;">
                                    <input type="hidden" name="NEXURA_enable_safe_browsing" value="0">
                                    <input type="checkbox" name="NEXURA_enable_safe_browsing" id="NEXURA_enable_safe_browsing" value="1" <?php checked( get_option('NEXURA_enable_safe_browsing', 0), 1 ); ?> />
                                    <span class="nexura-slider"></span>
                                </label>
                            </div>
                            <div style="font-size: 12px; color: #94a3b8; line-height: 1.6;">
                                <div><strong>Data Sent:</strong> Site domain name and URL</div>
                                <div><strong>Purpose:</strong> Verifies if the domain is flagged for phishing or malware distribution</div>
                                <div><strong>Trigger:</strong> Manual site audit or scheduled security score calculation</div>
                                <div><strong>Provider:</strong> Google LLC | <a href="https://policies.google.com/privacy" target="_blank" style="color: #38bdf8;">Privacy Policy</a></div>
                            </div>
                        </div>

                        <!-- 5. Have I Been Pwned -->
                        <div style="background: rgba(15, 23, 42, 0.6); padding: 14px 18px; border-radius: 10px; border: 1px solid var(--nexura-border);">
                            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
                                <strong style="color: #f8fafc; font-size: 14px;"><?php esc_html_e( 'Have I Been Pwned (HIBP)', 'nexura-security' ); ?></strong>
                                <label class="nexura-switch" style="margin: 0;">
                                    <input type="hidden" name="NEXURA_enable_hibp" value="0">
                                    <input type="checkbox" name="NEXURA_enable_hibp" id="NEXURA_enable_hibp" value="1" <?php checked( get_option('NEXURA_enable_hibp', 0), 1 ); ?> />
                                    <span class="nexura-slider"></span>
                                </label>
                            </div>
                            <div style="font-size: 12px; color: #94a3b8; line-height: 1.6;">
                                <div><strong>Data Sent:</strong> First 5 characters of SHA-1 password hash (k-Anonymity privacy model)</div>
                                <div><strong>Purpose:</strong> Checks if user passwords have been exposed in public data breaches</div>
                                <div><strong>Trigger:</strong> User password updates or login authentication when enabled</div>
                                <div><strong>Provider:</strong> Troy Hunt / HIBP API | <a href="https://haveibeenpwned.com/Privacy" target="_blank" style="color: #38bdf8;">Privacy Policy</a></div>
                            </div>
                        </div>

                        <!-- 6. AI Security Assistant -->
                        <div style="background: rgba(15, 23, 42, 0.6); padding: 14px 18px; border-radius: 10px; border: 1px solid var(--nexura-border);">
                            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
                                <strong style="color: #f8fafc; font-size: 14px;"><?php esc_html_e( 'AI Security Assistant', 'nexura-security' ); ?></strong>
                                <label class="nexura-switch" style="margin: 0;">
                                    <input type="hidden" name="NEXURA_enable_ai_assistant" value="0">
                                    <input type="checkbox" name="NEXURA_enable_ai_assistant" id="NEXURA_enable_ai_assistant" value="1" <?php checked( get_option('NEXURA_enable_ai_assistant', 0), 1 ); ?> />
                                    <span class="nexura-slider"></span>
                                </label>
                            </div>
                            <div style="font-size: 12px; color: #94a3b8; line-height: 1.6;">
                                <div><strong>Data Sent:</strong> Anonymized security logs or code snippets explicitly selected for analysis</div>
                                <div><strong>Purpose:</strong> AI-powered threat diagnosis, security advice, and auto-fix recommendations</div>
                                <div><strong>Trigger:</strong> Admin-initiated AI Security Assistant queries</div>
                                <div><strong>Provider:</strong> OpenAI / Google Gemini / Anthropic | <a href="https://openai.com/privacy" target="_blank" style="color: #38bdf8;">Privacy Policy</a></div>
                            </div>
                        </div>
                    </div>
                </td>
            </tr>
        </table>
        <?php if ( function_exists( 'submit_button' ) ) { submit_button(); } ?>
    </div>
</form>

<!-- Settings Export / Import -->
<div class="nexura-card nexura-fade-in" style="margin-top: 20px;">
    <h2><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4"></path></svg></span> <?php esc_html_e( 'Export / Import Settings', 'nexura-security' ); ?></h2>
    
    <table class="form-table">
        <tr>
            <th scope="row"><?php esc_html_e( 'Export Settings', 'nexura-security' ); ?></th>
            <td>
                <a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin.php?page=nexura-settings&nexura_export_settings=1' ), 'nexura_export_settings_action' ) ); ?>" class="button button-secondary">
                    <?php esc_html_e( 'Download Export (.json)', 'nexura-security' ); ?>
                </a>
                <p class="description">
                    <?php esc_html_e( 'Download a JSON file containing all your Nexura Security settings. This does not export logs or scan results.', 'nexura-security' ); ?>
                </p>
            </td>
        </tr>
        <tr>
            <th scope="row"><?php esc_html_e( 'Import Settings', 'nexura-security' ); ?></th>
            <td>
                <form method="post" action="<?php echo esc_url( admin_url( 'admin.php?page=nexura-settings' ) ); ?>" enctype="multipart/form-data">
                    <?php wp_nonce_field( 'nexura_import_settings_action', 'nexura_import_settings_nonce' ); ?>
                    <input type="file" name="nexura_import_file" accept=".json" required />
                    <button type="submit" name="nexura_import_settings_submit" class="button button-primary">
                        <?php esc_html_e( 'Import Settings', 'nexura-security' ); ?>
                    </button>
                    <p class="description">
                        <?php esc_html_e( 'Select a Nexura settings JSON file to import. This will overwrite your current settings.', 'nexura-security' ); ?>
                    </p>
                </form>
            </td>
        </tr>
    </table>
</div>
