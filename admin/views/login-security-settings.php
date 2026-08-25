<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template variables, not true globals.
// Get all WP roles
global $wp_roles;
$roles = $wp_roles->roles;

$roles_settings = get_option( 'NEXURA_2fa_roles', [] );
$grace_period = get_option( 'NEXURA_2fa_grace_period', '10' );

// User summary stats
global $wpdb;
$total_users = count_users();
$users_by_role = $total_users['avail_roles'];

// Get 2FA active count by role
$two_fa_active_counts = [];
foreach ( $roles as $role_key => $role_data ) {
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
    $count = $wpdb->get_var( $wpdb->prepare( "
        SELECT COUNT(u.ID) FROM {$wpdb->users} u
        INNER JOIN {$wpdb->usermeta} um ON u.ID = um.user_id
        INNER JOIN {$wpdb->usermeta} um2 ON u.ID = um2.user_id
        WHERE um.meta_key = %s AND um.meta_value LIKE %s
        AND um2.meta_key = 'NEXURA_2fa_enabled' AND um2.meta_value = '1'
    ", $wpdb->prefix . 'capabilities', '%' . $wpdb->esc_like( $role_key ) . '%' ) );
    $two_fa_active_counts[ $role_key ] = (int) $count;
}
?>

<div class="nexura-card nexura-fade-in" style="max-width: 1200px; margin: 20px 0;">
    <h2><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg></span> <?php esc_html_e( 'Login Security & reCAPTCHA Settings', 'nexura-security' ); ?></h2>
    <p><?php esc_html_e( 'Configure global Two-Factor Authentication policies, reCAPTCHA integration, and IP Allowlisting.', 'nexura-security' ); ?></p>
    
    <?php settings_errors( 'NEXURA_login_security_group' ); ?>


    <form method="post" action="options.php">
        <?php settings_fields( 'NEXURA_login_security_group' ); ?>

        <!-- Section: User Summary -->
        <div class="nexura-settings-section">
            <h3><?php esc_html_e( 'User Summary', 'nexura-security' ); ?></h3>
            <div class="nexura-settings-section-body">
                <table class="nexura-summary-table">
                    <thead>
                        <tr>
                            <th><?php esc_html_e( 'Role', 'nexura-security' ); ?></th>
                            <th><?php esc_html_e( 'Total Users', 'nexura-security' ); ?></th>
                            <th><?php esc_html_e( '2FA Active', 'nexura-security' ); ?></th>
                            <th><?php esc_html_e( '2FA Inactive', 'nexura-security' ); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ( $roles as $role_key => $role_data ) : 
                            $total = isset( $users_by_role[ $role_key ] ) ? $users_by_role[ $role_key ] : 0;
                            $active = isset( $two_fa_active_counts[ $role_key ] ) ? $two_fa_active_counts[ $role_key ] : 0;
                            $inactive = $total - $active;
                            if ( $total > 0 ) :
                        ?>
                        <tr>
                            <td><strong><?php echo esc_html( $role_data['name'] ); ?></strong></td>
                            <td><?php echo esc_html( $total ); ?></td>
                            <td><?php echo esc_html( $active ); ?></td>
                            <td><?php echo esc_html( $inactive ); ?></td>
                        </tr>
                        <?php 
                            endif;
                        endforeach; 
                        ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Section: 2FA Roles (Pro Features) -->
        <div class="nexura-settings-section">
            <h3><?php esc_html_e( '2FA Roles Policy (Pro)', 'nexura-security' ); ?></h3>
            <div class="nexura-settings-section-body">
                <?php 
                if ( has_action( 'nexura_login_security_pro_settings' ) ) {
                    do_action( 'nexura_login_security_pro_settings', $roles, $roles_settings, $grace_period );
                } else {
                    ?>
                    <div style="background: rgba(99, 102, 241, 0.05); border-left: 4px solid #6366f1; padding: 15px; border-radius: 4px;">
                        <p style="margin: 0; color: var(--nexura-text-primary);">
                            <strong><?php esc_html_e( 'Upgrade to Nexura Security Pro', 'nexura-security' ); ?></strong>
                            <br>
                            <?php esc_html_e( 'Get advanced features including Role-based 2FA Enforcement, Grace Periods, and "Remember Device" functionality to secure your team without friction.', 'nexura-security' ); ?>
                        </p>
                    </div>
                    <?php
                }
                ?>
            </div>
        </div>

        <!-- Section: WooCommerce & Custom Integrations -->
        <div class="nexura-settings-section">
            <h3><?php esc_html_e( 'WooCommerce & Custom Integrations', 'nexura-security' ); ?></h3>
            <div class="nexura-settings-section-body">
                <table class="nexura-settings-table">
                    <tr>
                        <th scope="row"><label for="NEXURA_wc_integration"><?php esc_html_e( 'WooCommerce Integration', 'nexura-security' ); ?></label></th>
                        <td>
                            <label class="nexura-switch">
                                <input type="checkbox" name="NEXURA_wc_integration" id="NEXURA_wc_integration" value="1" <?php checked( '1', get_option( 'NEXURA_wc_integration', '0' ) ); ?>>
                                <span class="nexura-slider"></span>
                            </label>
                            <p class="description"><?php esc_html_e( 'When enabled, reCAPTCHA and 2FA prompt support will be added to WooCommerce login and registration forms.', 'nexura-security' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="NEXURA_wc_account_menu"><?php esc_html_e( 'Show 2FA menu on WooCommerce Account page', 'nexura-security' ); ?></label></th>
                        <td>
                            <label class="nexura-switch">
                                <input type="checkbox" name="NEXURA_wc_account_menu" id="NEXURA_wc_account_menu" value="1" <?php checked( '1', get_option( 'NEXURA_wc_account_menu', '0' ) ); ?>>
                                <span class="nexura-slider"></span>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="NEXURA_2fa_shortcode"><?php esc_html_e( '2FA management shortcode', 'nexura-security' ); ?></label></th>
                        <td>
                            <label class="nexura-switch">
                                <input type="checkbox" name="NEXURA_2fa_shortcode" id="NEXURA_2fa_shortcode" value="1" <?php checked( '1', get_option( 'NEXURA_2fa_shortcode', '0' ) ); ?>>
                                <span class="nexura-slider"></span>
                            </label>
                            <p class="description"><?php esc_html_e( 'When enabled, the [nexura_2fa_management] shortcode may be used to provide access for users to manage 2FA settings on custom pages.', 'nexura-security' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="NEXURA_wc_single_column"><?php esc_html_e( 'Use single-column layout for shortcode', 'nexura-security' ); ?></label></th>
                        <td>
                            <label class="nexura-switch">
                                <input type="checkbox" name="NEXURA_wc_single_column" id="NEXURA_wc_single_column" value="1" <?php checked( '1', get_option( 'NEXURA_wc_single_column', '1' ) ); ?>>
                                <span class="nexura-slider"></span>
                            </label>
                        </td>
                    </tr>
                </table>
            </div>
        </div>

        <!-- Section: Brute Force Protection -->
        <div class="nexura-settings-section">
            <h3><?php esc_html_e( 'Brute Force Protection', 'nexura-security' ); ?></h3>
            <div class="nexura-settings-section-body">
                <table class="nexura-settings-table">
                    <tr>
                        <th scope="row"><label for="NEXURA_brute_force_max_attempts"><?php esc_html_e( 'Max Login Attempts', 'nexura-security' ); ?></label></th>
                        <td>
                            <input type="number" name="NEXURA_brute_force_max_attempts" id="NEXURA_brute_force_max_attempts" value="<?php echo esc_attr( get_option( 'NEXURA_brute_force_max_attempts', '5' ) ); ?>" class="regular-text" style="width: 100px;">
                            <p class="description"><?php esc_html_e( 'Number of allowed failed attempts before the IP is locked out (Default: 5).', 'nexura-security' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="NEXURA_brute_force_lockout"><?php esc_html_e( 'Lockout Duration (seconds)', 'nexura-security' ); ?></label></th>
                        <td>
                            <input type="number" name="NEXURA_brute_force_lockout" id="NEXURA_brute_force_lockout" value="<?php echo esc_attr( get_option( 'NEXURA_brute_force_lockout', '1800' ) ); ?>" class="regular-text" style="width: 100px;">
                            <p class="description"><?php esc_html_e( 'How long an IP is locked out after reaching the max attempts (Default: 1800 seconds / 30 mins).', 'nexura-security' ); ?></p>
                        </td>
                    </tr>
                </table>
            </div>
        </div>

        <!-- Section: XML-RPC -->
        <div class="nexura-settings-section">
            <h3><?php esc_html_e( 'XML-RPC Authentication', 'nexura-security' ); ?></h3>
            <div class="nexura-settings-section-body">
                <table class="nexura-settings-table">
                    <tr>
                        <th scope="row"><label for="NEXURA_require_xmlrpc_2fa"><?php esc_html_e( 'Require 2FA for XML-RPC', 'nexura-security' ); ?></label></th>
                        <td>
                            <label class="nexura-switch">
                                <input type="checkbox" name="NEXURA_require_xmlrpc_2fa" id="NEXURA_require_xmlrpc_2fa" value="1" <?php checked( '1', get_option( 'NEXURA_require_xmlrpc_2fa', '0' ) ); ?>>
                                <span class="nexura-slider"></span>
                            </label>
                            <p class="description"><?php esc_html_e( 'If enabled, XML-RPC calls that require authentication will fail if the user has 2FA enabled but is not using an Application Password.', 'nexura-security' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="NEXURA_disable_xmlrpc"><?php esc_html_e( 'Disable XML-RPC', 'nexura-security' ); ?></label></th>
                        <td>
                            <label class="nexura-switch">
                                <input type="checkbox" name="NEXURA_disable_xmlrpc" id="NEXURA_disable_xmlrpc" value="1" <?php checked( '1', get_option( 'NEXURA_disable_xmlrpc', '0' ) ); ?>>
                                <span class="nexura-slider"></span>
                            </label>
                            <p class="description"><?php esc_html_e( 'If enabled, XML-RPC requests will be rejected globally.', 'nexura-security' ); ?></p>
                        </td>
                    </tr>
                </table>
            </div>
        </div>

        <!-- Section: reCAPTCHA -->
        <div class="nexura-settings-section">
            <h3><?php esc_html_e( 'reCAPTCHA (v3)', 'nexura-security' ); ?></h3>
            <div class="nexura-settings-section-body">
                <table class="nexura-settings-table">
                    <tr>
                        <th scope="row"><label for="NEXURA_recaptcha_enabled"><?php esc_html_e( 'Enable reCAPTCHA', 'nexura-security' ); ?></label></th>
                        <td>
                            <label class="nexura-switch">
                                <input type="checkbox" name="NEXURA_recaptcha_enabled" id="NEXURA_recaptcha_enabled" value="1" <?php checked( '1', get_option( 'NEXURA_recaptcha_enabled', '0' ) ); ?>>
                                <span class="nexura-slider"></span>
                            </label>
                            <p class="description"><?php esc_html_e( 'Enable Google reCAPTCHA v3 on the login and user registration pages (including WooCommerce).', 'nexura-security' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="NEXURA_recaptcha_site_key"><?php esc_html_e( 'Site Key', 'nexura-security' ); ?></label></th>
                        <td>
                            <input type="text" name="NEXURA_recaptcha_site_key" id="NEXURA_recaptcha_site_key" value="<?php echo esc_attr( get_option( 'NEXURA_recaptcha_site_key', '' ) ); ?>" class="regular-text">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="NEXURA_recaptcha_secret_key"><?php esc_html_e( 'Secret Key', 'nexura-security' ); ?></label></th>
                        <td>
                            <input type="password" name="NEXURA_recaptcha_secret_key" id="NEXURA_recaptcha_secret_key" value="<?php echo esc_attr( get_option( 'NEXURA_recaptcha_secret_key', '' ) ); ?>" class="regular-text">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="NEXURA_recaptcha_threshold"><?php esc_html_e( 'Human/Bot Threshold Score', 'nexura-security' ); ?></label></th>
                        <td>
                            <select name="NEXURA_recaptcha_threshold" id="NEXURA_recaptcha_threshold">
                                <?php
                                $thresholds = [ '0.1', '0.2', '0.3', '0.4', '0.5', '0.6', '0.7', '0.8', '0.9' ];
                                $current_t = get_option( 'NEXURA_recaptcha_threshold', '0.5' );
                                foreach ( $thresholds as $t ) {
                                    $label = $t === '0.5' ? $t . ' (default)' : $t;
                                    echo '<option value="' . esc_attr($t) . '" ' . selected( $current_t, $t, false ) . '>' . esc_html($label) . '</option>';
                                }
                                ?>
                            </select>
                            <p class="description"><?php esc_html_e( 'A reCAPTCHA score equal to or higher than this value will be considered human. Anything lower will be treated as a bot.', 'nexura-security' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="NEXURA_recaptcha_test_mode"><?php esc_html_e( 'Run reCAPTCHA in test mode', 'nexura-security' ); ?></label></th>
                        <td>
                            <label class="nexura-switch">
                                <input type="checkbox" name="NEXURA_recaptcha_test_mode" id="NEXURA_recaptcha_test_mode" value="1" <?php checked( '1', get_option( 'NEXURA_recaptcha_test_mode', '0' ) ); ?>>
                                <span class="nexura-slider"></span>
                            </label>
                            <p class="description"><?php esc_html_e( 'While in test mode, reCAPTCHA will score login and registration requests but will not actually block them.', 'nexura-security' ); ?></p>
                        </td>
                    </tr>
                </table>
            </div>
        </div>

        <!-- Section: General -->
        <div class="nexura-settings-section">
            <h3><?php esc_html_e( 'General Settings', 'nexura-security' ); ?></h3>
            <div class="nexura-settings-section-body">
                <table class="nexura-settings-table">
                    <tr>
                        <th scope="row"><label for="NEXURA_ip_allowlist"><?php esc_html_e( 'Allowlisted IP addresses that bypass 2FA and reCAPTCHA', 'nexura-security' ); ?></label></th>
                        <td>
                            <textarea name="NEXURA_ip_allowlist" id="NEXURA_ip_allowlist" rows="5" class="large-text code"><?php echo esc_textarea( get_option( 'NEXURA_ip_allowlist', '' ) ); ?></textarea>
                            <p class="description"><?php esc_html_e( 'Allowlisted IPs must be placed on separate lines. You can specify ranges using wildcards (e.g. 192.168.1.*).', 'nexura-security' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="NEXURA_ntp_sync"><?php esc_html_e( 'NTP Time Sync', 'nexura-security' ); ?></label></th>
                        <td>
                            <label class="nexura-switch">
                                <input type="checkbox" name="NEXURA_ntp_sync" id="NEXURA_ntp_sync" value="1" <?php checked( '1', get_option( 'NEXURA_ntp_sync', '1' ) ); ?>>
                                <span class="nexura-slider"></span>
                            </label>
                            <p class="description"><?php esc_html_e( 'NTP is a protocol that allows for remote time synchronization to ensure your site has the most accurate time for TOTP-based authentication.', 'nexura-security' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="NEXURA_show_last_login"><?php esc_html_e( 'Show last login column on WP Users page', 'nexura-security' ); ?></label></th>
                        <td>
                            <label class="nexura-switch">
                                <input type="checkbox" name="NEXURA_show_last_login" id="NEXURA_show_last_login" value="1" <?php checked( '1', get_option( 'NEXURA_show_last_login', '1' ) ); ?>>
                                <span class="nexura-slider"></span>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="NEXURA_delete_data_on_deactivation"><?php esc_html_e( 'Delete Login Security tables and data on deactivation', 'nexura-security' ); ?></label></th>
                        <td>
                            <label class="nexura-switch">
                                <input type="checkbox" name="NEXURA_delete_data_on_deactivation" id="NEXURA_delete_data_on_deactivation" value="1" <?php checked( '1', get_option( 'NEXURA_delete_data_on_deactivation', '0' ) ); ?>>
                                <span class="nexura-slider"></span>
                            </label>
                            <p class="description"><?php esc_html_e( 'If enabled, all settings and 2FA records will be deleted on plugin deactivation.', 'nexura-security' ); ?></p>
                        </td>
                    </tr>
                </table>
            </div>
        </div>

        <?php submit_button( __( 'Save Changes', 'nexura-security' ), 'primary', 'submit', true, [ 'class' => 'nexura-btn nexura-btn-primary' ] ); ?>
    </form>
</div>
