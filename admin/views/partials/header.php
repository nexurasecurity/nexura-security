<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

// Determine current page for active sidebar highlighting
// phpcs:ignore WordPress.Security.NonceVerification.Recommended
$NEXURA_current_page = isset( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : 'nexura';
$NEXURA_current_slug = str_replace( 'nexura-', '', $NEXURA_current_page );
if ( $NEXURA_current_page === 'nexura' ) {
    $NEXURA_current_slug = 'dashboard';
}

// Get high issues count for badge
global $wpdb;
$NEXURA_total_issues = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}NEXURA_scan_results" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
?>

<div class="wrap nexura-wrap">

    <!-- ========== TOP BAR ========== -->
    <div class="nexura-topbar">
        <div class="nexura-topbar-brand">
            <div class="nexura-topbar-logo"><img src="<?php echo esc_url( NEXURA_PLUGIN_URL . 'admin/img/icon.png' ); ?>" alt="Nexura Security Logo" ></div>
            <div>
                <div class="nexura-topbar-title">Nexura Security <span class="nexura-plan-badge"><?php echo esc_html( ucfirst( nexura_is_pro() ? 'Pro' : 'Free' ) ); ?></span></div>
                <div class="nexura-topbar-subtitle">Enterprise Security Control Center</div>
            </div>
        </div>
        <div class="nexura-topbar-actions">
            <span class="nexura-live-dot green"></span>
            <span style="color: var(--nexura-green); font-size: 12px; font-weight: 600;">MONITORING ACTIVE</span>
            <a href="<?php echo esc_url( admin_url( 'admin.php?page=nexura-malware-scan' ) ); ?>" class="nexura-btn nexura-btn-primary"><svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="vertical-align: text-bottom; margin-right: 4px;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0zM10 7v3m0 0v3m0-3h3m-3 0H7"></path></svg> Run Scan</a>
            <a href="<?php echo esc_url( admin_url( 'admin.php?page=nexura-google-safe-browsing' ) ); ?>" class="nexura-btn nexura-btn-secondary"><svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="vertical-align: text-bottom; margin-right: 4px;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"></path></svg> Check GSB</a>
        </div>
    </div>

    <!-- ========== LAYOUT ========== -->
    <div class="nexura-dashboard-layout">

        <!-- ===== SIDEBAR NAVIGATION ===== -->
        <nav class="nexura-sidebar">
            <div class="nexura-sidebar-label">Navigation</div>

            <a href="<?php echo esc_url( admin_url( 'admin.php?page=nexura-dashboard' ) ); ?>" class="nexura-nav-item <?php echo $NEXURA_current_slug === 'dashboard' ? 'active' : ''; ?>">
                <span class="nexura-nav-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"></path></svg></span> Dashboard
            </a>
            <?php if ( function_exists('nexurasec_fs') && nexurasec_fs()->is_registered() ) : ?>
            <a href="<?php echo esc_url( nexurasec_fs()->get_account_url() ); ?>" class="nexura-nav-item" style="border-left: 3px solid #ec4899;">
                <span class="nexura-nav-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path></svg></span> My Account
            </a>
            <?php endif; ?>
            <a href="<?php echo esc_url( admin_url( 'admin.php?page=nexura-malware-scan' ) ); ?>" class="nexura-nav-item <?php echo $NEXURA_current_slug === 'malware-scan' ? 'active' : ''; ?>">
                <span class="nexura-nav-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0zM10 7v3m0 0v3m0-3h3m-3 0H7"></path></svg></span> Malware Scan
            </a>
            <a href="<?php echo esc_url( admin_url( 'admin.php?page=nexura-issues-detected' ) ); ?>" class="nexura-nav-item <?php echo $NEXURA_current_slug === 'issues-detected' ? 'active' : ''; ?>">
                <span class="nexura-nav-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg></span> Issues Detected
                <?php if ( $NEXURA_total_issues > 0 ) : ?>
                    <span class="nexura-nav-badge"><?php echo esc_html( $NEXURA_total_issues ); ?></span>
                <?php endif; ?>
            </a>
            <a href="<?php echo esc_url( admin_url( 'admin.php?page=nexura-file-integrity' ) ); ?>" class="nexura-nav-item <?php echo $NEXURA_current_slug === 'file-integrity' ? 'active' : ''; ?>">
                <span class="nexura-nav-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg></span> File Integrity
            </a>
            <a href="<?php echo esc_url( admin_url( 'admin.php?page=nexura-hardening' ) ); ?>" class="nexura-nav-item <?php echo $NEXURA_current_slug === 'hardening' ? 'active' : ''; ?>">
                <span class="nexura-nav-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg></span> Hardening
            </a>

            <a href="<?php echo esc_url( admin_url( 'admin.php?page=nexura-google-safe-browsing' ) ); ?>" class="nexura-nav-item <?php echo $NEXURA_current_slug === 'google-safe-browsing' ? 'active' : ''; ?>">
                <span class="nexura-nav-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"></path></svg></span> Google Safe Browsing
            </a>

            <div class="nexura-sidebar-label" style="margin-top: 12px;">System</div>

            <a href="<?php echo esc_url( admin_url( 'admin.php?page=nexura-ssl-settings' ) ); ?>" class="nexura-nav-item <?php echo $NEXURA_current_slug === 'ssl-settings' ? 'active' : ''; ?>">
                <span class="nexura-nav-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"></path></svg></span> SSL & HTTPS
            </a>

            <a href="<?php echo esc_url( admin_url( 'admin.php?page=nexura-login-security' ) ); ?>" class="nexura-nav-item <?php echo $NEXURA_current_slug === 'login-security' ? 'active' : ''; ?>">
                <span class="nexura-nav-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg></span> Login Security
            </a>

            <a href="<?php echo esc_url( admin_url( 'admin.php?page=nexura-settings' ) ); ?>" class="nexura-nav-item <?php echo $NEXURA_current_slug === 'settings' ? 'active' : ''; ?>">
                <span class="nexura-nav-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path></svg></span> Settings
            </a>
          
            <a href="<?php echo esc_url( admin_url( 'admin.php?page=nexura-about' ) ); ?>" class="nexura-nav-item <?php echo $NEXURA_current_slug === 'about' ? 'active' : ''; ?>">
                <span class="nexura-nav-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg></span> About
            </a>

            <!-- PRO Features Hook -->
            <?php do_action( 'nexura_pro_sidebar_menus', $NEXURA_current_slug ); ?>

            <div style="margin-top: 20px;"></div>

            <!-- Support & Upgrade -->
            <a href="<?php echo esc_url( admin_url( 'admin.php?page=nexura-contact' ) ); ?>" class="nexura-nav-item <?php echo $NEXURA_current_slug === 'contact' ? 'active' : ''; ?>">
                <span class="nexura-nav-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg></span> Contact Us
            </a>
            <a href="https://wordpress.org/support/plugin/nexura-security/" class="nexura-nav-item" target="_blank">
                <span class="nexura-nav-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 8h2a2 2 0 012 2v6a2 2 0 01-2 2h-2v4l-4-4H9a1.994 1.994 0 01-1.414-.586m0 0L11 14h4a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2v4l.586-.586z"></path></svg></span> Support Forum
            </a>
            <?php if ( function_exists('nexurasec_fs') && nexurasec_fs()->is_pricing_page_visible() ) : ?>
            <a href="<?php echo esc_url( function_exists('nexurasec_fs') ? nexurasec_fs()->get_upgrade_url() : '' ); ?>" class="nexura-nav-item" style="color: #10b981; font-weight: 600;">
                <span class="nexura-nav-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg></span> Upgrade ➤
            </a>
            <?php endif; ?>
        </nav>

        <!-- ===== MAIN CONTENT ===== -->
        <main class="nexura-main">
            <!-- Hidden H2 to anchor WordPress/Freemius notices at the top of the main area -->
            <h2 style="display: none; margin: 0; padding: 0;"></h2>
