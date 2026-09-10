<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template variables, not true globals.
$active_tab = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : '2fa'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
$base_url = admin_url( 'admin.php?page=nexura-login-security' );
?>
<div class="wrap">
    <h1><?php esc_html_e( 'Login Security', 'nexura-security' ); ?></h1>
    
    <h2 class="nav-tab-wrapper">
        <a href="<?php echo esc_url( add_query_arg( 'tab', '2fa', $base_url ) ); ?>" class="nav-tab <?php echo $active_tab === '2fa' ? 'nav-tab-active' : ''; ?>">
            <?php esc_html_e( 'Two-Factor Authentication', 'nexura-security' ); ?>
        </a>
        <a href="<?php echo esc_url( add_query_arg( 'tab', 'locked_ips', $base_url ) ); ?>" class="nav-tab <?php echo $active_tab === 'locked_ips' ? 'nav-tab-active' : ''; ?>">
            <?php esc_html_e( 'Locked IPs', 'nexura-security' ); ?>
        </a>
        <a href="<?php echo esc_url( add_query_arg( 'tab', 'settings', $base_url ) ); ?>" class="nav-tab <?php echo $active_tab === 'settings' ? 'nav-tab-active' : ''; ?>">
            <?php esc_html_e( 'Settings', 'nexura-security' ); ?>
        </a>
    </h2>

    <div class="nexura-login-security-tab-content">
        <?php
        if ( $active_tab === '2fa' ) {
            require NEXURA_PLUGIN_DIR . 'admin/views/2fa-settings.php';
        } elseif ( $active_tab === 'locked_ips' ) {
            require NEXURA_PLUGIN_DIR . 'admin/views/login-security-locked-ips.php';
        } elseif ( $active_tab === 'settings' ) {
            require NEXURA_PLUGIN_DIR . 'admin/views/login-security-settings.php';
        }
        ?>
    </div>
</div>
