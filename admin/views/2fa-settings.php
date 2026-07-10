<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

$current_user = wp_get_current_user();
$two_factor = new \Nexura_Security\Two_Factor_Auth();

// Handle form submission for disabling 2FA
$message = '';
if ( isset( $_POST['NEXURA_2fa_action'] ) && $_POST['NEXURA_2fa_action'] === 'disable' && check_admin_referer( 'NEXURA_disable_2fa' ) ) {
    update_user_meta( $current_user->ID, 'NEXURA_2fa_enabled', '0' );
    // Rotate secret and clear recovery codes
    update_user_meta( $current_user->ID, 'NEXURA_2fa_secret', $two_factor->generate_secret() );
    delete_user_meta( $current_user->ID, 'NEXURA_2fa_recovery_codes' );
    $message = '<div class="notice notice-warning inline"><p>' . esc_html__( 'Two-Factor Authentication has been disabled. A new secret key has been generated.', 'nexura-security' ) . '</p></div>';
}

$is_enabled = get_user_meta( $current_user->ID, 'NEXURA_2fa_enabled', true );
$secret     = get_user_meta( $current_user->ID, 'NEXURA_2fa_secret', true );

if ( empty( $secret ) ) {
    $secret = $two_factor->generate_secret();
    update_user_meta( $current_user->ID, 'NEXURA_2fa_secret', $secret );
}

$site_name_clean = preg_replace( '/[^a-zA-Z0-9]/', '', get_bloginfo( 'name' ) );
if ( empty( $site_name_clean ) ) {
    $site_name_clean = 'WordPress';
}
$site_name = rawurlencode( $site_name_clean );
$user_login = rawurlencode( $current_user->user_login );
$otpauth_url = 'otpauth://totp/' . $site_name . ':' . $user_login . '?secret=' . $secret . '&issuer=' . $site_name;
?>

<div class="nexura-card nexura-fade-in" style="max-width: 1000px; margin: 20px 0;">
    <h2><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"></path></svg></span> <?php esc_html_e( 'Two-Factor Authentication (2FA)', 'nexura-security' ); ?></h2>
    
    <?php echo $message; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>

    <?php if ( $is_enabled === '1' ) : ?>
        <div style="background: #eaffea; padding: 20px; border-left: 4px solid var(--nexura-green); margin-bottom: 20px; border-radius: 4px;">
            <h3 style="color: var(--nexura-green); font-size: 18px; margin-top: 0; margin-bottom: 10px;"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="vertical-align: text-bottom;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg> <?php esc_html_e( '2FA is currently ACTIVE for your account.', 'nexura-security' ); ?></h3>
            <p style="margin-bottom: 0; color: #555;"><?php esc_html_e( 'Your account is secured. You will be prompted for an authentication code when logging in.', 'nexura-security' ); ?></p>
        </div>
        
        <form method="post" action="">
            <?php wp_nonce_field( 'NEXURA_disable_2fa' ); ?>
            <input type="hidden" name="NEXURA_2fa_action" value="disable">
            <p>
                <button type="submit" class="button button-secondary" onclick="return confirm('<?php esc_attr_e( 'Are you sure you want to disable 2FA? This will reduce your account security.', 'nexura-security' ); ?>');">
                    <?php esc_html_e( 'Deactivate 2FA', 'nexura-security' ); ?>
                </button>
            </p>
        </form>

    <?php else : ?>
        <p><?php esc_html_e( 'Secure your account by requiring a 6-digit code from your phone (via Google Authenticator or Authy) when logging in.', 'nexura-security' ); ?></p>
        
        <div style="display: flex; gap: 20px; flex-wrap: wrap;">
            
            <!-- Column 1: QR Code -->
            <div style="flex: 1; min-width: 300px; background: var(--nexura-bg-card, #111827); color: var(--nexura-text-primary, #f1f5f9); border: 1px solid var(--nexura-border, rgba(99, 102, 241, 0.15)); padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); border-radius: 8px;">
                <h3 style="margin-top: 0; color: var(--nexura-text-primary, #f1f5f9); border-bottom: 1px solid var(--nexura-border, rgba(99, 102, 241, 0.15)); padding-bottom: 10px;"><?php esc_html_e( '1. Scan Code or Enter Key', 'nexura-security' ); ?></h3>
                <p style="color: var(--nexura-text-secondary, #94a3b8);"><?php esc_html_e( 'Scan the code below with your authenticator app to add this account. Some authenticator apps also allow you to type in the text version instead.', 'nexura-security' ); ?></p>
                
                <div style="text-align: center; margin: 20px 0;">
                    <div id="nexura-2fa-qr" data-url="<?php echo esc_attr( $otpauth_url ); ?>" style="border: 5px solid #fff; border-radius: 8px; display: inline-block;"></div>
                </div>
                
                <div style="background: var(--nexura-bg-primary, #0b0f1a); padding: 10px; text-align: center; font-family: monospace; font-size: 14px; border: 1px solid var(--nexura-border, rgba(99, 102, 241, 0.15)); color: var(--nexura-text-primary, #f1f5f9); border-radius: 4px;">
                    <?php echo esc_html( $secret ); ?>
                </div>
            </div>

            <!-- Column 2: Verify and Recovery -->
            <div style="flex: 1; min-width: 300px; background: var(--nexura-bg-card, #111827); color: var(--nexura-text-primary, #f1f5f9); border: 1px solid var(--nexura-border, rgba(99, 102, 241, 0.15)); padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); border-radius: 8px; overflow: hidden;">
                <h3 style="margin-top: 0; color: var(--nexura-text-primary, #f1f5f9); border-bottom: 1px solid var(--nexura-border, rgba(99, 102, 241, 0.15)); padding-bottom: 10px;"><?php esc_html_e( '2. Enter Code from Authenticator App', 'nexura-security' ); ?></h3>
                
                <div id="nexura-2fa-setup-form-wrapper">
                    <p style="color: var(--nexura-text-secondary, #94a3b8);"><?php esc_html_e( 'Enter the code from your authenticator app below to verify and activate two-factor authentication for this account.', 'nexura-security' ); ?></p>
                    <div style="display: flex; gap: 10px; align-items: center; justify-content: center; margin: 20px 0;">
                        <input type="text" id="nexura_2fa_setup_code" placeholder="123456" style="font-size: 24px; padding: 10px; width: 150px; text-align: center; letter-spacing: 2px; color: var(--nexura-text-primary, #f1f5f9); background: var(--nexura-bg-primary, #0b0f1a); border: 1px solid var(--nexura-border, rgba(99, 102, 241, 0.15)); border-radius: 4px;" maxlength="6">
                    </div>
                    <div style="text-align: right; background: rgba(99, 102, 241, 0.05); padding: 15px 20px; margin: 20px -20px -20px; border-top: 1px solid var(--nexura-border, rgba(99, 102, 241, 0.15));">
                        <button type="button" id="nexura_verify_2fa_btn" class="button button-primary button-large" data-secret="<?php echo esc_attr( $secret ); ?>">
                            <?php esc_html_e( 'ACTIVATE', 'nexura-security' ); ?>
                        </button>
                    </div>
                </div>

                <!-- Hidden Success Area for Recovery Codes -->
                <div id="nexura-2fa-setup-success" style="display: none;">
                    <div class="notice notice-success inline" style="margin: 0 0 20px 0; background: var(--nexura-green-bg); border-left-color: var(--nexura-green); border-radius: 4px;"><p style="color: var(--nexura-text-primary);"><?php esc_html_e( 'Two-Factor Authentication is now enabled.', 'nexura-security' ); ?></p></div>
                    
                    <h4 style="color: var(--nexura-text-primary);"><?php esc_html_e( 'Download Recovery Codes', 'nexura-security' ); ?></h4>
                    <p class="description" style="color: var(--nexura-text-secondary);"><?php esc_html_e( 'Use one of these 5 codes to log in if you lose access to your authenticator device. Each one may be used only once.', 'nexura-security' ); ?></p>
                    
                    <div id="nexura-recovery-codes-display" style="font-family: monospace; background: var(--nexura-bg-primary); padding: 15px; border: 1px solid var(--nexura-border); border-radius: 4px; margin: 15px 0; text-align: center; line-height: 1.8; color: var(--nexura-text-primary);">
                        <!-- Generated via JS -->
                    </div>

                    <div style="text-align: center;">
                        <button type="button" id="nexura_download_recovery_btn" class="button button-secondary">
                            <span class="dashicons dashicons-download" style="margin-top:4px;"></span> <?php esc_html_e( 'DOWNLOAD', 'nexura-security' ); ?>
                        </button>
                    </div>

                    <div style="text-align: right; margin-top: 20px;">
                        <button type="button" onclick="location.reload();" class="button button-primary"><?php esc_html_e( 'Done', 'nexura-security' ); ?></button>
                    </div>
                </div>

            </div>

        </div>
    <?php endif; ?>
</div>
