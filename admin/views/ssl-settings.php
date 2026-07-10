<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

$site_url = get_option('siteurl');
$home_url = get_option('home');

$is_https_site = ( strpos( $site_url, 'https://' ) === 0 );
$is_https_home = ( strpos( $home_url, 'https://' ) === 0 );
$is_ssl_forced = get_option('NEXURA_force_ssl', false);
$plan = nexura_is_pro() ? 'pro' : 'free';

// Health Diagnostics
$diagnostics = [];

if ( ! $is_https_site || ! $is_https_home ) {
    $diagnostics[] = [
        'status' => 'error',
        'title'  => 'Mixed Content / HTTP URLs Detected',
        'desc'   => 'Your WordPress Address (URL) or Site Address (URL) is currently set to http:// instead of https://. This will cause mixed content warnings.',
        'fix'    => 'Go to Settings > General and update your URLs to use https://.'
    ];
} else {
    $diagnostics[] = [
        'status' => 'success',
        'title'  => 'WordPress URLs use HTTPS',
        'desc'   => 'Your Site and Home URLs are correctly configured for SSL.',
        'fix'    => ''
    ];
}

if ( ! $is_ssl_forced ) {
    $diagnostics[] = [
        'status' => 'warning',
        'title'  => 'SSL Not Forced via .htaccess',
        'desc'   => 'Visitors can still access your site via an insecure http:// connection.',
        'fix'    => 'Enable the "Force SSL (.htaccess)" setting below to redirect all insecure traffic.'
    ];
} else {
    $diagnostics[] = [
        'status' => 'success',
        'title'  => 'SSL Enforcement Active',
        'desc'   => 'All traffic is being securely redirected to HTTPS via .htaccess.',
        'fix'    => ''
    ];
}

if ( ! is_ssl() && ! isset( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) ) {
    $diagnostics[] = [
        'status' => 'warning',
        'title'  => 'No SSL Detected on Current Connection',
        'desc'   => 'You are currently accessing this dashboard over an insecure connection, or your server is behind a proxy that strips SSL headers.',
        'fix'    => 'Ensure your hosting provider has issued a valid SSL certificate (like Let\'s Encrypt).'
    ];
}

?>

<div class="nexura-main-content">
    <div class="nexura-header">
        <h1>SSL & HTTPS Settings</h1>
        <p>Monitor your SSL certificate health and enforce secure connections.</p>
    </div>

    <?php do_action( 'nexura_pro_ssl_manager_hook' ); ?>

    <!-- SSL Health Diagnostics -->
    <div class="nexura-card">
        <h2>SSL Diagnostics</h2>
        <p>Nexura has audited your SSL configuration:</p>
        
        <div class="nexura-diagnostics-list">
            <?php foreach ( $diagnostics as $item ) : ?>
                <div class="nexura-diagnostic-item nexura-diagnostic-<?php echo esc_attr( $item['status'] ); ?>" style="padding: 15px; border-left: 4px solid <?php echo $item['status'] === 'success' ? '#22c55e' : ($item['status'] === 'error' ? '#ef4444' : '#eab308'); ?>; background: #fff; margin-bottom: 15px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-radius: 4px;">
                    <h4 style="margin: 0 0 5px 0; color: #1f2937;"><?php echo esc_html( $item['title'] ); ?></h4>
                    <p style="margin: 0 0 10px 0; color: #4b5563; font-size: 14px;"><?php echo esc_html( $item['desc'] ); ?></p>
                    <?php if ( ! empty( $item['fix'] ) ) : ?>
                        <div style="font-size: 13px; color: #d97706; font-weight: 500;">
                            <strong>Solution:</strong> <?php echo esc_html( $item['fix'] ); ?>
                        </div>
                    <?php endif; ?>
                </div>
            <?php endforeach; ?>
        </div>
    </div>

    <!-- SSL Settings Form -->
    <div class="nexura-card" style="margin-top: 20px;">
        <h2>Enforce SSL</h2>
        <form method="post" action="options.php">
            <?php
            settings_fields( 'NEXURA_ssl_group' );
            ?>
            <table class="form-table">
                <tr>
                    <th scope="row">Force SSL (.htaccess)</th>
                    <td>
                        <label class="nexura-switch">
                            <input type="checkbox" name="NEXURA_force_ssl" value="1" <?php checked( 1, get_option( 'NEXURA_force_ssl' ), true ); ?>>
                            <span class="nexura-slider"></span>
                        </label>
                        <p class="description">Automatically redirects all <code>http://</code> traffic to <code>https://</code> using Apache rewrite rules. This requires a valid SSL certificate.</p>
                    </td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>
    </div>

</div>
