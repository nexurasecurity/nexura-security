<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}
// phpcs:ignoreFile WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( isset( $_POST['NEXURA_captcha_save'] ) && check_admin_referer( 'NEXURA_captcha_nonce' ) ) {
    $type   = isset( $_POST['NEXURA_captcha_type'] ) ? sanitize_text_field( wp_unslash( $_POST['NEXURA_captcha_type'] ) ) : 'turnstile';
    $site   = isset( $_POST['NEXURA_captcha_site_key'] ) ? sanitize_text_field( wp_unslash( $_POST['NEXURA_captcha_site_key'] ) ) : '';
    $secret = isset( $_POST['NEXURA_captcha_secret_key'] ) ? sanitize_text_field( wp_unslash( $_POST['NEXURA_captcha_secret_key'] ) ) : '';
    
    update_option( 'NEXURA_captcha_type', $type );
    update_option( 'NEXURA_captcha_site_key', $site );
    update_option( 'NEXURA_captcha_secret_key', $secret );
    echo '<div class="nexura-alert nexura-alert-success" style="margin-bottom: 20px; padding: 15px; background: #ecfdf5; color: #065f46; border-radius: 6px; border-left: 4px solid #10b981;"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="vertical-align: text-bottom;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg> Settings saved successfully.</div>';
}

$NEXURA_captcha_type = get_option( 'NEXURA_captcha_type', 'turnstile' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
$NEXURA_site_key = get_option( 'NEXURA_captcha_site_key', '' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
$NEXURA_secret_key = get_option( 'NEXURA_captcha_secret_key', '' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
?>

<div class="nexura-card nexura-fade-in">
    <h2><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h2v2H9V9zm4 0h2v2h-2V9zm-4 6h6v2H9v-2z"></path></svg></span> <?php esc_html_e( 'Human Verification Settings', 'nexura-security' ); ?></h2>
    <p><?php esc_html_e( 'Configure Cloudflare Turnstile or Google reCAPTCHA to prevent bots from bypassing security blocks.', 'nexura-security' ); ?></p>

    <form method="post" action="">
        <?php wp_nonce_field( 'NEXURA_captcha_nonce' ); ?>
        
        <div class="nexura-form-group" style="margin-top: 20px; margin-bottom: 15px;">
            <label class="nexura-form-label" style="display:block; margin-bottom: 5px; font-weight: 600; color: #e2e8f0;"><?php esc_html_e( 'CAPTCHA Provider', 'nexura-security' ); ?></label>
            <select name="NEXURA_captcha_type" class="nexura-form-control" style="width: 100%; max-width: 400px; padding: 10px; background: #1e293b; border: 1px solid #334155; color: #fff; border-radius: 4px;">
                <option value="turnstile" <?php selected( $NEXURA_captcha_type, 'turnstile' ); ?>>Cloudflare Turnstile</option>
                <option value="recaptcha" <?php selected( $NEXURA_captcha_type, 'recaptcha' ); ?>>Google reCAPTCHA v2</option>
            </select>
        </div>

        <div class="nexura-form-group" style="margin-bottom: 15px;">
            <label class="nexura-form-label" style="display:block; margin-bottom: 5px; font-weight: 600; color: #e2e8f0;"><?php esc_html_e( 'Site Key', 'nexura-security' ); ?></label>
            <input type="text" name="NEXURA_captcha_site_key" class="nexura-form-control" style="width: 100%; max-width: 400px; padding: 10px; background: #1e293b; border: 1px solid #334155; color: #fff; border-radius: 4px;" value="<?php echo esc_attr( $NEXURA_site_key ); ?>" placeholder="Enter your Site Key">
        </div>

        <div class="nexura-form-group" style="margin-bottom: 15px;">
            <label class="nexura-form-label" style="display:block; margin-bottom: 5px; font-weight: 600; color: #e2e8f0;"><?php esc_html_e( 'Secret Key', 'nexura-security' ); ?></label>
            <input type="password" name="NEXURA_captcha_secret_key" class="nexura-form-control" style="width: 100%; max-width: 400px; padding: 10px; background: #1e293b; border: 1px solid #334155; color: #fff; border-radius: 4px;" value="<?php echo esc_attr( $NEXURA_secret_key ); ?>" placeholder="Enter your Secret Key">
        </div>

        <div style="margin-top: 20px;">
            <button type="submit" name="NEXURA_captcha_save" class="nexura-btn nexura-btn-primary"><?php esc_html_e( 'Save Settings', 'nexura-security' ); ?></button>
        </div>
    </form>
</div>
