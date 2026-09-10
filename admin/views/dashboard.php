<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

// Fetch dynamic data for the dashboard
global $wpdb;
$NEXURA_table_name    = $wpdb->prefix . 'NEXURA_scan_results';
$NEXURA_total_issues  = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}NEXURA_scan_results" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
$NEXURA_high_issues   = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}NEXURA_scan_results WHERE risk_score = %s", 'High' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
$NEXURA_medium_issues = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}NEXURA_scan_results WHERE risk_score = %s", 'Medium' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
$NEXURA_total_scanned = (int) get_option( 'NEXURA_scan_total', 0 );

$NEXURA_critical_issues = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}NEXURA_scan_results WHERE risk_score = %s", 'Critical' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared

$NEXURA_score = \Nexura_Security\Security_Score::get_score();
$NEXURA_risk = \Nexura_Security\Security_Score::get_risk_level( $NEXURA_score );

// If any malware exists, the site is NOT protected. Force score drop.
if ( $NEXURA_total_issues > 0 && $NEXURA_score >= 80 ) {
    $NEXURA_score -= 20;
    $NEXURA_risk = \Nexura_Security\Security_Score::get_risk_level( $NEXURA_score );
}

$NEXURA_score_class = strtolower( str_replace(' ', '-', $NEXURA_risk['label']) );
if ( $NEXURA_score >= 80 ) {
    $NEXURA_score_class = 'safe';
} elseif ( $NEXURA_score >= 50 ) {
    $NEXURA_score_class = 'warning';
} else {
    $NEXURA_score_class = 'critical';
}
$NEXURA_score_text  = $NEXURA_risk['label'];

$NEXURA_recent_alerts = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}NEXURA_scan_results ORDER BY id DESC LIMIT 8", ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared

// Fetch attack logs
$NEXURA_attack_logs = [];
$table_attack_logs = $wpdb->prefix . 'NEXURA_attack_logs';
$actual_table_attack_logs = $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table_attack_logs ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
if ( $actual_table_attack_logs && strcasecmp( $actual_table_attack_logs, $table_attack_logs ) === 0 ) {
    // --- SYNC PRO WAF LOGS ---
    $upload_dir = wp_upload_dir();
    $waf_log_file = $upload_dir['basedir'] . '/nexura-security/waf_attacks.log';
    if ( file_exists( $waf_log_file ) && class_exists( '\Nexura_Security\Attack_Logger' ) ) {
        $lines = file( $waf_log_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES );
        if ( ! empty( $lines ) ) {
            // Empty the file immediately to prevent race conditions
            @file_put_contents( $waf_log_file, '' );
            foreach ( $lines as $line ) {
                $data = json_decode( $line, true );
                if ( ! empty( $data['ip'] ) && ! empty( $data['reason'] ) ) {
                    \Nexura_Security\Attack_Logger::log_attack( $data['ip'], sanitize_text_field( $data['reason'] ), 'Blocked' );
                }
            }
        }
    }
    // -------------------------

    // Pagination setup
    $atk_per_page    = 7;
    $atk_page        = isset( $_GET['atk_page'] ) ? max( 1, (int) $_GET['atk_page'] ) : 1; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    $atk_offset      = ( $atk_page - 1 ) * $atk_per_page;
    $atk_total       = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table_attack_logs}" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
    $atk_total_pages = max( 1, (int) ceil( $atk_total / $atk_per_page ) );

    $NEXURA_attack_logs = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table_attack_logs} ORDER BY id DESC LIMIT %d OFFSET %d", $atk_per_page, $atk_offset ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
}
$NEXURA_circumference = 2 * 3.14159 * 65;
$NEXURA_offset = $NEXURA_circumference - ( $NEXURA_score / 100 ) * $NEXURA_circumference;
?>

<!-- ===== STATUS RIBBON ===== -->
<div class="nexura-status-ribbon nexura-fade-in">
    <div class="nexura-metric-card <?php echo $NEXURA_score >= 80 ? 'safe' : ( $NEXURA_score >= 50 ? 'warning' : 'critical' ); ?>">
        <div class="nexura-metric-icon <?php echo $NEXURA_score >= 80 ? 'safe' : ( $NEXURA_score >= 50 ? 'warning' : 'critical' ); ?>"><svg width="24" height="24" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg></div>
        <div class="nexura-metric-body">
            <div class="nexura-metric-value"><?php echo esc_html( $NEXURA_score ); ?><span style="font-size:16px; color: var(--nexura-text-muted);">/100</span></div>
            <div class="nexura-metric-label">Security Score</div>
        </div>
    </div>
    <div class="nexura-metric-card <?php echo $NEXURA_total_issues > 0 ? 'warning' : 'safe'; ?>">
        <div class="nexura-metric-icon <?php echo $NEXURA_total_issues > 0 ? 'warning' : 'safe'; ?>"><svg width="24" height="24" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0zM10 7v3m0 0v3m0-3h3m-3 0H7"></path></svg></div>
        <div class="nexura-metric-body">
            <div class="nexura-metric-value"><?php echo esc_html( $NEXURA_total_issues ); ?></div>
            <div class="nexura-metric-label">Issues Detected</div>
        </div>
    </div>
    <div class="nexura-metric-card info">
        <div class="nexura-metric-icon info"><svg width="24" height="24" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"></path></svg></div>
        <div class="nexura-metric-body">
            <div class="nexura-metric-value"><?php echo esc_html( number_format( $NEXURA_total_scanned ) ); ?></div>
            <div class="nexura-metric-label">Files Scanned</div>
        </div>
    </div>
    <div class="nexura-metric-card <?php echo $NEXURA_high_issues > 0 ? 'critical' : 'safe'; ?>">
        <div class="nexura-metric-icon <?php echo $NEXURA_high_issues > 0 ? 'critical' : 'safe'; ?>"><svg width="24" height="24" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg></div>
        <div class="nexura-metric-body">
            <div class="nexura-metric-value"><?php echo esc_html( $NEXURA_high_issues ); ?></div>
            <div class="nexura-metric-label">High Risk Threats</div>
        </div>
    </div>
</div>

<!-- ===== ROW: Score + Quick Actions + Notifications ===== -->
<div class="nexura-grid-3 nexura-fade-in" style="animation-delay: 0.15s;">

    <!-- Security Score Ring -->
    <div class="nexura-card">
        <h2><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path></svg></span> Security Score</h2>
        <div class="nexura-score-ring-wrap">
            <div class="nexura-score-ring">
                <svg width="160" height="160" viewBox="0 0 160 160">
                    <circle class="nexura-score-ring-bg" cx="80" cy="80" r="65" />
                    <circle class="nexura-score-ring-fill <?php echo esc_attr( $NEXURA_score_class ); ?>"
                            cx="80" cy="80" r="65"
                            stroke-dasharray="<?php echo esc_attr( $NEXURA_circumference ); ?>"
                            stroke-dashoffset="<?php echo esc_attr( $NEXURA_offset ); ?>" />
                </svg>
                <div class="nexura-score-value">
                    <div class="nexura-score-number"><?php echo esc_html( $NEXURA_score ); ?></div>
                    <div class="nexura-score-label">Score</div>
                </div>
            </div>
            <div class="nexura-score-status <?php echo esc_attr( $NEXURA_score_class ); ?>">
                <?php echo esc_html( $NEXURA_score_text ); ?>
            </div>
        </div>
    </div>

    <!-- Quick Actions -->
    <div class="nexura-card">
        <h2><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg></span> Quick Actions</h2>
        <div class="nexura-quick-actions">
            <a href="?page=nexura-malware-scan" class="nexura-quick-action">
                <span class="nexura-quick-action-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0zM10 7v3m0 0v3m0-3h3m-3 0H7"></path></svg></span>
                <span>Run Malware Scan</span>
            </a>
            <a href="?page=nexura-file-integrity" class="nexura-quick-action">
                <span class="nexura-quick-action-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg></span>
                <span>Check File Integrity</span>
            </a>
            <a href="?page=nexura-google-safe-browsing" class="nexura-quick-action">
                <span class="nexura-quick-action-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"></path></svg></span>
                <span>Google Safe Browsing</span>
            </a>
            <a href="?page=nexura-vulnerability-audit" class="nexura-quick-action">
                <span class="nexura-quick-action-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg></span>
                <span>Vulnerability Audit</span>
            </a>
            <a href="?page=nexura-performance" class="nexura-quick-action">
                <span class="nexura-quick-action-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg></span>
                <span>Performance Audit</span>
            </a>
            <a href="?page=nexura-hardening" class="nexura-quick-action">
                <span class="nexura-quick-action-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg></span>
                <span>Hardening Rules</span>
            </a>
            <a href="#" id="nexura-quick-backup-db" class="nexura-quick-action">
                <span class="nexura-quick-action-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4"></path></svg></span>
                <span>Backup Database</span>
            </a>
            <a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin.php?page=nexura-dashboard&nexura_download_report=1' ), 'nexura_download_report_action' ) ); ?>" class="nexura-quick-action" target="_blank">
                <span class="nexura-quick-action-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg></span>
                <span>Download PDF Report</span>
            </a>
        </div>
    </div>

    <!-- Notifications -->
    <div class="nexura-card">
        <h2><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"></path></svg></span> Notifications</h2>
        

        
        <?php if ( $NEXURA_high_issues > 0 ) : ?>
            <div class="nexura-notification critical">
                <span class="nexura-notification-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg></span>
                <div class="nexura-notification-body">
                    <div class="nexura-notification-title">High-Risk Threats Found</div>
                    <div class="nexura-notification-text"><?php echo esc_html( $NEXURA_high_issues ); ?> critical issue(s) need immediate attention.</div>
                </div>
                <span class="nexura-notification-time">Now</span>
            </div>
        <?php endif; ?>
        <?php if ( $NEXURA_medium_issues > 0 ) : ?>
            <div class="nexura-notification warning">
                <span class="nexura-notification-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg></span>
                <div class="nexura-notification-body">
                    <div class="nexura-notification-title">Medium-Risk Issues</div>
                    <div class="nexura-notification-text"><?php echo esc_html( $NEXURA_medium_issues ); ?> medium issue(s) detected during scan.</div>
                </div>
                <span class="nexura-notification-time">Recent</span>
            </div>
        <?php endif; ?>
        <?php if ( $NEXURA_total_scanned > 0 ) : ?>
            <div class="nexura-notification safe">
                <span class="nexura-notification-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg></span>
                <div class="nexura-notification-body">
                    <div class="nexura-notification-title">Scan Completed</div>
                    <div class="nexura-notification-text"><?php echo esc_html( number_format( $NEXURA_total_scanned ) ); ?> files processed successfully.</div>
                </div>
                <span class="nexura-notification-time">Last run</span>
            </div>
        <?php else : ?>
            <div class="nexura-notification info">
                <span class="nexura-notification-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg></span>
                <div class="nexura-notification-body">
                    <div class="nexura-notification-title">No Scans Yet</div>
                    <div class="nexura-notification-text">Run your first malware scan to establish a security baseline.</div>
                </div>
            </div>
        <?php endif; ?>
        <div class="nexura-notification info">
            <span class="nexura-notification-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg></span>
            <div class="nexura-notification-body">
                <div class="nexura-notification-title">Login Protection Active</div>
                <div class="nexura-notification-text">Brute-force attack protection is monitoring login attempts.</div>
            </div>
        </div>
    </div>
</div>

<!-- ===== ROW: Charts ===== -->
<div class="nexura-grid-2 nexura-fade-in" style="animation-delay: 0.3s;">
    <div class="nexura-card">
        <h2><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z"></path></svg></span> Malware Risk Trend</h2>
        <div class="nexura-chart-wrap">
            <canvas id="nexura-chart-malware-trend"></canvas>
        </div>
    </div>
    <div class="nexura-card">
        <h2><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 3.055A9.001 9.001 0 1020.945 13H11V3.055z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.488 9H15V3.512A9.025 9.025 0 0120.488 9z"></path></svg></span> File Integrity Overview</h2>
        <div class="nexura-chart-wrap">
            <canvas id="nexura-chart-integrity"></canvas>
        </div>
    </div>
</div>

<!-- ===== ROW: Login Security Stats ===== -->
<div class="nexura-grid-2 nexura-fade-in" style="animation-delay: 0.4s;">
    <div class="nexura-card" style="grid-column: span 2;">
        <h2><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg></span> reCAPTCHA Score Trends (Last 7 Days)</h2>
        <div class="nexura-chart-wrap" style="height: 300px;">
            <canvas id="nexura-chart-recaptcha-trend"></canvas>
        </div>
    </div>
</div>

<!-- ===== Recent Alerts Table ===== -->
<div class="nexura-card nexura-fade-in" style="animation-delay: 0.45s;">
    <h2><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"></path></svg></span> Recent Alerts</h2>
    <?php if ( ! empty( $NEXURA_recent_alerts ) ) : ?>
        <table class="nexura-alerts-table">
            <thead>
                <tr>
                    <?php do_action( 'nexura_dashboard_alerts_table_header' ); ?>
                    <th>Pattern Detected</th>
                    <th>Risk Level</th>
                    <th>Confidence</th>
                    <th>Scan Time</th>
                </tr>
            </thead>
            <tbody>
                <?php $NEXURA_alert_index = 0; ?>
                <?php foreach ( $NEXURA_recent_alerts as $NEXURA_alert ) : ?>
                    <?php
                    $NEXURA_malware_name = $NEXURA_alert['pattern'];
                    if ( strpos( $NEXURA_malware_name, 'Regex Match: ' ) === 0 ) {
                        $NEXURA_malware_name = str_replace( 'Regex Match: ', '', $NEXURA_malware_name );
                    } elseif ( strpos( $NEXURA_malware_name, 'DB Post ID ' ) === 0 ) {
                        $NEXURA_malware_name = preg_replace( '/DB Post ID \d+: /', '', $NEXURA_malware_name );
                    } elseif ( strpos( $NEXURA_malware_name, 'DB Option ' ) === 0 ) {
                        $NEXURA_malware_name = preg_replace( '/DB Option ".*": /', '', $NEXURA_malware_name );
                    } elseif ( strpos( $NEXURA_malware_name, 'ghost_sig_' ) === 0 || $NEXURA_malware_name === 'ghost_malware_detected' ) {
                        $NEXURA_malware_name = 'Ghost Malware Variant';
                    } elseif ( strpos( $NEXURA_malware_name, 'suspicious_upload_ext:' ) === 0 ) {
                        $NEXURA_malware_name = 'Suspicious Executable Upload';
                    } elseif ( strpos( $NEXURA_malware_name, 'community_learned_' ) === 0 ) {
                        $NEXURA_malware_name = 'Community Blocked Signature';
                    }

                    if ( substr( $NEXURA_malware_name, 0, 1 ) === '/' && strlen( $NEXURA_malware_name ) > 20 ) {
                        $NEXURA_malware_name = 'Custom Malware Payload';
                    } elseif ( strpos( $NEXURA_malware_name, '_' ) !== false ) {
                        $NEXURA_malware_name = ucwords( str_replace( '_', ' ', $NEXURA_malware_name ) );
                    }

                    ?>
                    <tr>
                        <?php do_action( 'nexura_dashboard_alerts_table_row', $NEXURA_alert ); ?>
                        <td><strong><?php echo esc_html( $NEXURA_malware_name ); ?></strong></td>
                        <td>
                            <?php
                            $NEXURA_badge_class = 'info';
                            if ( $NEXURA_alert['risk_score'] === 'Critical' ) $NEXURA_badge_class = 'critical';
                            if ( $NEXURA_alert['risk_score'] === 'High' )     $NEXURA_badge_class = 'critical';
                            if ( $NEXURA_alert['risk_score'] === 'Medium' )   $NEXURA_badge_class = 'warning';
                            if ( $NEXURA_alert['risk_score'] === 'Low' )      $NEXURA_badge_class = 'safe';
                            ?>
                            <span class="nexura-badge <?php echo esc_attr( $NEXURA_badge_class ); ?>">
                                <?php echo esc_html( $NEXURA_alert['risk_score'] ); ?>
                            </span>
                        </td>
                        <td><?php echo esc_html( $NEXURA_alert['confidence'] ); ?>%</td>
                        <td style="color: var(--nexura-text-muted); font-size: 12px;"><?php echo esc_html( $NEXURA_alert['scan_time'] ); ?></td>
                    </tr>
                    <?php $NEXURA_alert_index++; ?>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php else : ?>
        <div style="text-align: center; padding: 40px 0; color: var(--nexura-text-muted);">
            <div style="margin-bottom: 12px; display: flex; justify-content: center;"><svg width="48" height="48" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="color:#10b981;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg></div>
            <p style="font-size: 15px; font-weight: 600;">No alerts to display.</p>
            <p style="font-size: 13px;">Run your first scan to begin monitoring.</p>
        </div>
    <?php endif; ?>
</div>

<!-- ===== Live Traffic & Blocked Attacks Table ===== -->
<div class="nexura-card nexura-fade-in" style="animation-delay: 0.5s;">
    <h2><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg></span> Live Traffic & Attack Logs</h2>
    <?php if ( ! empty( $NEXURA_attack_logs ) ) : ?>
        <div style="max-height: 420px; overflow-y: auto; border-radius: 8px; border: 1px solid var(--nexura-border); background: rgba(15, 23, 42, 0.4);">
            <table class="nexura-alerts-table" id="nexura-attack-logs-table" style="margin: 0; width: 100%; border-collapse: collapse;">
                <thead>
                    <tr style="position: sticky; top: 0; background: #0f172a; z-index: 10;">
                        <th style="padding: 12px 14px; font-size: 11px; font-weight: 700; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.8px; border-bottom: 1px solid #334155;">IP Address</th>
                        <th style="padding: 12px 14px; font-size: 11px; font-weight: 700; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.8px; border-bottom: 1px solid #334155;">Country</th>
                        <th style="padding: 12px 14px; font-size: 11px; font-weight: 700; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.8px; border-bottom: 1px solid #334155;">Attack Type</th>
                        <th style="padding: 12px 14px; font-size: 11px; font-weight: 700; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.8px; border-bottom: 1px solid #334155;">Action Taken</th>
                        <th style="padding: 12px 14px; font-size: 11px; font-weight: 700; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.8px; border-bottom: 1px solid #334155;">Time</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ( $NEXURA_attack_logs as $log ) : ?>
                        <tr style="border-bottom: 1px solid rgba(51, 65, 85, 0.4); transition: background 0.2s;">
                            <td style="padding: 10px 14px; font-family: monospace; font-size: 13px; font-weight: 700; color: #f8fafc;">
                                <?php echo esc_html( $log['ip_address'] ); ?>
                            </td>
                            <td class="nexura-country-cell" data-ip="<?php echo esc_attr( $log['ip_address'] ); ?>" style="padding: 10px 14px; font-size: 13px; color: #cbd5e1;">
                                <?php if ( ! empty( $log['country'] ) && $log['country'] !== 'Unknown' ) : ?>
                                    <?php
                                    $c_name = trim( $log['country'] );
                                    $c_code = '';
                                    $name_map = [
                                        'united states' => 'us', 'usa' => 'us', 'united kingdom' => 'gb', 'uk' => 'gb',
                                        'south korea' => 'kr', 'korea' => 'kr', 'north korea' => 'kp', 'bangladesh' => 'bd',
                                        'india' => 'in', 'germany' => 'de', 'france' => 'fr', 'canada' => 'ca',
                                        'australia' => 'au', 'china' => 'cn', 'russia' => 'ru', 'russian federation' => 'ru',
                                        'japan' => 'jp', 'brazil' => 'br', 'italy' => 'it', 'spain' => 'es',
                                        'netherlands' => 'nl', 'switzerland' => 'ch', 'sweden' => 'se', 'norway' => 'no',
                                        'finland' => 'fi', 'poland' => 'pl', 'ukraine' => 'ua', 'turkey' => 'tr',
                                        'saudi arabia' => 'sa', 'united arab emirates' => 'ae', 'uae' => 'ae',
                                        'vietnam' => 'vn', 'thailand' => 'th', 'singapore' => 'sg', 'malaysia' => 'my',
                                        'indonesia' => 'id', 'pakistan' => 'pk', 'egypt' => 'eg', 'south africa' => 'za',
                                        'mexico' => 'mx', 'argentina' => 'ar', 'colombia' => 'co', 'chile' => 'cl'
                                    ];
                                    $l_name = strtolower( $c_name );
                                    if ( isset( $name_map[ $l_name ] ) ) {
                                        $c_code = $name_map[ $l_name ];
                                    } elseif ( strlen( $c_name ) === 2 ) {
                                        $c_code = strtolower( $c_name );
                                    }
                                    $flag_url = $c_code ? 'https://flagcdn.com/16x12/' . $c_code . '.png' : '';
                                    ?>
                                    <?php if ( $flag_url ) : ?>
                                        <img src="<?php echo esc_url( $flag_url ); ?>" alt="<?php echo esc_attr( $c_name ); ?>" style="margin-right: 6px; vertical-align: middle;">
                                    <?php endif; ?>
                                    <?php echo esc_html( $c_name ); ?>
                                <?php else: ?>
                                    <span style="color: #64748b; font-size: 12px; font-style: italic;">Unknown (Pro)</span>
                                <?php endif; ?>
                            </td>
                            <td style="padding: 10px 14px;">
                                <?php
                                $type_text = strtoupper( $log['attack_type'] );
                                $type_style = 'background: rgba(245, 158, 11, 0.12); border: 1px solid rgba(245, 158, 11, 0.3); color: #f59e0b;';
                                if ( strpos( $type_text, 'WAF' ) !== false || strpos( $type_text, 'BOT' ) !== false || strpos( $type_text, 'MALICIOUS' ) !== false ) {
                                    $type_style = 'background: rgba(239, 68, 68, 0.12); border: 1px solid rgba(239, 68, 68, 0.3); color: #ef4444;';
                                }
                                ?>
                                <span style="<?php echo esc_attr( $type_style ); ?> padding: 3px 12px; border-radius: 20px; font-size: 11px; font-weight: 700; text-transform: uppercase; display: inline-block;">
                                    <?php echo esc_html( $type_text ); ?>
                                </span>
                            </td>
                            <td style="padding: 10px 14px;">
                                <?php
                                $action_text = strtoupper( $log['action_taken'] );
                                $action_style = 'background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.3); color: #10b981;';
                                if ( strpos( $action_text, 'BLOCK' ) !== false ) {
                                    $action_style = 'background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.3); color: #10b981;';
                                }
                                ?>
                                <span style="<?php echo esc_attr( $action_style ); ?> padding: 3px 12px; border-radius: 20px; font-size: 11px; font-weight: 700; text-transform: uppercase; display: inline-block;">
                                    <?php echo esc_html( $action_text ); ?>
                                </span>
                            </td>
                            <td style="padding: 10px 14px; color: #94a3b8; font-size: 12px; white-space: nowrap;">
                                <?php echo esc_html( wp_date( 'F j, Y g:i a', strtotime( $log['timestamp'] ) ) ); ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <?php if ( isset( $atk_total_pages ) && $atk_total_pages > 1 ) : ?>
        <div style="display: flex; align-items: center; justify-content: space-between; margin-top: 14px; flex-wrap: wrap; gap: 10px;">
            <div style="font-size: 12px; color: #64748b;">
                <?php
                $atk_start = ( ( $atk_page - 1 ) * $atk_per_page ) + 1;
                $atk_end   = min( $atk_page * $atk_per_page, $atk_total );
                /* translators: 1: first row, 2: last row, 3: total rows */
                printf( esc_html__( 'Showing %1$d–%2$d of %3$d entries', 'nexura-security' ), $atk_start, $atk_end, $atk_total );
                ?>
            </div>
            <div style="display: flex; gap: 4px; flex-wrap: wrap;">
                <?php
                $base_url = remove_query_arg( 'atk_page' );
                // Previous
                if ( $atk_page > 1 ) :
                    ?>
                    <a href="<?php echo esc_url( add_query_arg( 'atk_page', $atk_page - 1, $base_url ) ); ?>" style="padding: 5px 12px; border-radius: 6px; font-size: 12px; font-weight: 600; color: #cbd5e1; background: rgba(51,65,85,0.6); border: 1px solid #334155; text-decoration: none; transition: all 0.2s;" onmouseover="this.style.background='rgba(99,102,241,0.2)'" onmouseout="this.style.background='rgba(51,65,85,0.6)'">&laquo; <?php esc_html_e( 'Prev', 'nexura-security' ); ?></a>
                <?php endif; ?>

                <?php
                // Page numbers — show max 7 around current
                $range   = 3;
                $start_p = max( 1, $atk_page - $range );
                $end_p   = min( $atk_total_pages, $atk_page + $range );
                if ( $start_p > 1 ) :
                    ?>
                    <a href="<?php echo esc_url( add_query_arg( 'atk_page', 1, $base_url ) ); ?>" style="padding: 5px 10px; border-radius: 6px; font-size: 12px; color: #94a3b8; background: rgba(51,65,85,0.4); border: 1px solid #334155; text-decoration: none;">1</a>
                    <?php if ( $start_p > 2 ) echo '<span style="padding: 5px 4px; color:#475569;">…</span>'; ?>
                <?php endif; ?>

                <?php for ( $p = $start_p; $p <= $end_p; $p++ ) :
                    $is_current = ( $p === $atk_page );
                    $p_style = $is_current
                        ? 'padding: 5px 10px; border-radius: 6px; font-size: 12px; font-weight: 700; color: #fff; background: #6366f1; border: 1px solid #6366f1; text-decoration: none;'
                        : 'padding: 5px 10px; border-radius: 6px; font-size: 12px; color: #94a3b8; background: rgba(51,65,85,0.4); border: 1px solid #334155; text-decoration: none;';
                    ?>
                    <a href="<?php echo esc_url( add_query_arg( 'atk_page', $p, $base_url ) ); ?>" style="<?php echo esc_attr( $p_style ); ?>"><?php echo (int) $p; ?></a>
                <?php endfor; ?>

                <?php if ( $end_p < $atk_total_pages ) :
                    if ( $end_p < $atk_total_pages - 1 ) echo '<span style="padding: 5px 4px; color:#475569;">…</span>';
                    ?>
                    <a href="<?php echo esc_url( add_query_arg( 'atk_page', $atk_total_pages, $base_url ) ); ?>" style="padding: 5px 10px; border-radius: 6px; font-size: 12px; color: #94a3b8; background: rgba(51,65,85,0.4); border: 1px solid #334155; text-decoration: none;"><?php echo (int) $atk_total_pages; ?></a>
                <?php endif; ?>

                <?php if ( $atk_page < $atk_total_pages ) : ?>
                    <a href="<?php echo esc_url( add_query_arg( 'atk_page', $atk_page + 1, $base_url ) ); ?>" style="padding: 5px 12px; border-radius: 6px; font-size: 12px; font-weight: 600; color: #cbd5e1; background: rgba(51,65,85,0.6); border: 1px solid #334155; text-decoration: none; transition: all 0.2s;" onmouseover="this.style.background='rgba(99,102,241,0.2)'" onmouseout="this.style.background='rgba(51,65,85,0.6)'"><?php esc_html_e( 'Next', 'nexura-security' ); ?> &raquo;</a>
                <?php endif; ?>
            </div>
        </div>
        <?php endif; ?>

        <!-- Smart JavaScript for Country Detection via Proprietary Cloudflare Worker -->
        <script>
        document.addEventListener('DOMContentLoaded', function() {
            const countryCells = document.querySelectorAll('.nexura-country-cell');
            const uniqueIps = new Set();
            
            countryCells.forEach(cell => {
                const ip = cell.getAttribute('data-ip');
                if (ip && cell.textContent.trim() === 'Unknown (Pro)') {
                    uniqueIps.add(ip);
                }
            });

            if (uniqueIps.size > 0) {
                const ipArray = Array.from(uniqueIps);
                
                fetch('https://sgs-db-worker.sentinel-guard-security.workers.dev/v1/geoip', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ips: ipArray })
                })
                .then(res => res.json())
                .then(data => {
                    const countryMap = data.data || {};

                    countryCells.forEach(cell => {
                        const ip = cell.getAttribute('data-ip');
                        if (countryMap[ip] && countryMap[ip].code) {
                            const flagUrl = 'https://flagcdn.com/16x12/' + countryMap[ip].code.toLowerCase() + '.png';
                            cell.innerHTML = '<img src="' + flagUrl + '" alt="' + countryMap[ip].code + '" style="margin-right: 6px; vertical-align: middle;"> ' + countryMap[ip].country;
                        } else if (cell.textContent.trim() === 'Unknown (Pro)') {
                            cell.innerHTML = '<span style="color: #64748b; font-size: 12px; font-style: italic;">Unknown</span>';
                        }
                    });
                })
                .catch(err => console.error('GeoIP Error:', err));
            }
        });
        </script>

    <?php else : ?>
        <div style="text-align: center; padding: 40px 0; color: var(--nexura-text-muted); border: 1px solid var(--nexura-border); border-radius: 8px; background: rgba(15, 23, 42, 0.4);">
            <div style="margin-bottom: 12px; display: flex; justify-content: center;"><svg width="48" height="48" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="color:#6366f1; opacity:0.6;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg></div>
            <p style="font-size: 15px; font-weight: 600;">No attacks recorded.</p>
            <p style="font-size: 13px;">Your site traffic is clean.</p>
        </div>
    <?php endif; ?>
</div>
