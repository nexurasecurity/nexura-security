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
$NEXURA_total_issues = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}NEXURA_scan_results" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
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
            <?php 
            $sidebar_sections = \Nexura_Security\Admin::get_sidebar_structure();
            $is_first_section = true;

            foreach ( $sidebar_sections as $section_label => $items ) :
                if ( empty( $items ) ) continue;

                if ( $is_first_section ) {
                    echo '<div class="nexura-sidebar-label">' . esc_html( $section_label ) . '</div>';
                    $is_first_section = false;
                } else {
                    echo '<div class="nexura-sidebar-label" style="margin-top: 12px;">' . esc_html( $section_label ) . '</div>';
                }

                foreach ( $items as $slug => $data ) :
                    $active_class = ( $NEXURA_current_slug === $slug ? 'active' : '' );
                    ?>
                    <a href="<?php echo esc_url( admin_url( $data['url'] ) ); ?>" class="nexura-nav-item <?php echo esc_attr( $active_class ); ?>">
                        <span class="nexura-nav-icon"><?php echo $data['icon']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></span> <?php echo wp_kses( $data['label'], [ 'span' => [ 'class' => [], 'style' => [] ] ] ); ?>
                        <?php if ( $slug === 'issues-detected' && $NEXURA_total_issues > 0 ) : ?>
                            <span class="nexura-nav-badge"><?php echo esc_html( $NEXURA_total_issues ); ?></span>
                        <?php endif; ?>
                    </a>
                    <?php

                    // Inject Freemius "My Account" right after Dashboard
                    if ( $slug === 'dashboard' && function_exists('nsp_fs') && nsp_fs()->is_registered() ) :
                    ?>
                    <a href="<?php echo esc_url( nsp_fs()->get_account_url() ); ?>" class="nexura-nav-item" style="border-left: 3px solid #ec4899;">
                        <span class="nexura-nav-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path></svg></span> My Account
                    </a>
                    <?php
                    endif;
                endforeach;

            endforeach;
            ?>

            <!-- Support & Upgrade -->
            <a href="<?php echo esc_url( admin_url( 'admin.php?page=nexura-help' ) ); ?>" class="nexura-nav-item <?php echo $NEXURA_current_slug === 'help' ? 'active' : ''; ?>">
                <span class="nexura-nav-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg></span> Contact Us
            </a>
            <a href="https://wordpress.org/support/plugin/nexura-security/" class="nexura-nav-item" target="_blank">
                <span class="nexura-nav-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 8h2a2 2 0 012 2v6a2 2 0 01-2 2h-2v4l-4-4H9a1.994 1.994 0 01-1.414-.586m0 0L11 14h4a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2v4l.586-.586z"></path></svg></span> Support Forum
            </a>
            <?php if ( ( ! function_exists('nexura_is_pro') || ! nexura_is_pro() ) && function_exists('nsp_fs') && nsp_fs()->is_pricing_page_visible() ) : ?>
            <a href="<?php echo esc_url( function_exists('nsp_fs') ? nsp_fs()->get_upgrade_url() : '' ); ?>" class="nexura-nav-item" style="color: #10b981; font-weight: 600;">
                <span class="nexura-nav-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg></span> Upgrade ➤
            </a>
            <?php endif; ?>
        </nav>

        <!-- ===== MAIN CONTENT ===== -->
        <main class="nexura-main">
            <!-- Notice Trap: WordPress JS moves admin notices after the first H2.
                 This container captures them and hides everything inside. -->
            <div style="height:0;max-height:0;overflow:hidden;padding:0;margin:0;line-height:0;">
                <h2></h2>
            </div>
