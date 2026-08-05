<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

// Fetch dynamic data for the dashboard
global $wpdb;
$NEXURA_table_name    = $wpdb->prefix . 'NEXURA_scan_results';
$NEXURA_total_issues  = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}NEXURA_scan_results" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
$NEXURA_high_issues   = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}NEXURA_scan_results WHERE risk_score = %s", 'High' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
$NEXURA_medium_issues = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}NEXURA_scan_results WHERE risk_score = %s", 'Medium' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
$NEXURA_total_scanned = (int) get_option( 'NEXURA_scan_total', 0 );

$NEXURA_critical_issues = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}NEXURA_scan_results WHERE risk_score = %s", 'Critical' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

$NEXURA_score = 100;
if ( $NEXURA_critical_issues > 0 ) $NEXURA_score -= min( 80, $NEXURA_critical_issues * 30 );
if ( $NEXURA_high_issues > 0 )     $NEXURA_score -= min( 50, $NEXURA_high_issues * 15 );
if ( $NEXURA_medium_issues > 0 )   $NEXURA_score -= min( 30, $NEXURA_medium_issues * 5 );

// If any malware exists, the site is NOT protected. Force score below 80.
if ( $NEXURA_total_issues > 0 && $NEXURA_score >= 80 ) {
    $NEXURA_score = 79;
}
$NEXURA_score = max( 0, $NEXURA_score );


if ( $NEXURA_score >= 80 ) {
    $NEXURA_score_class = 'safe';
    $NEXURA_score_text  = 'Protected';
} elseif ( $NEXURA_score >= 50 ) {
    $NEXURA_score_class = 'warning';
    $NEXURA_score_text  = 'Action Required';
} else {
    $NEXURA_score_class = 'critical';
    $NEXURA_score_text  = 'At Risk';
}

$NEXURA_recent_alerts = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}NEXURA_scan_results ORDER BY id DESC LIMIT 8", ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

// Fetch attack logs
$NEXURA_attack_logs = [];
$table_attack_logs = $wpdb->prefix . 'NEXURA_attack_logs';
if ( $wpdb->get_var( "SHOW TABLES LIKE '$table_attack_logs'" ) === $table_attack_logs ) {
    
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

    $NEXURA_attack_logs = $wpdb->get_results( "SELECT * FROM {$table_attack_logs} ORDER BY id DESC LIMIT 20", ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
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
                            if ( $NEXURA_alert['risk_score'] === 'High' )   $NEXURA_badge_class = 'critical';
                            if ( $NEXURA_alert['risk_score'] === 'Medium' ) $NEXURA_badge_class = 'warning';
                            if ( $NEXURA_alert['risk_score'] === 'Low' )    $NEXURA_badge_class = 'safe';
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
        <table class="nexura-alerts-table" id="nexura-attack-logs-table">
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Country</th>
                    <th>Attack Type</th>
                    <th>Action Taken</th>
                    <th>Time</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ( $NEXURA_attack_logs as $log ) : ?>
                    <tr>
                        <td style="font-family: monospace; font-size: 13px;">
                            <strong><?php echo esc_html( $log['ip_address'] ); ?></strong>
                        </td>
                        <td class="nexura-country-cell" data-ip="<?php echo esc_attr( $log['ip_address'] ); ?>">
                            <?php if ( $log['country'] !== 'Unknown' ) : ?>
                                <?php echo esc_html( $log['country'] ); ?>
                            <?php else: ?>
                                <span style="color: var(--nexura-text-muted); font-size: 12px; font-style: italic;">Detecting...</span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <?php
                            $type_badge = 'warning';
                            if ( strpos( strtolower( $log['attack_type'] ), 'malicious' ) !== false || strpos( strtolower( $log['attack_type'] ), 'bot' ) !== false ) {
                                $type_badge = 'critical';
                            }
                            ?>
                            <span class="nexura-badge <?php echo esc_attr( $type_badge ); ?>">
                                <?php echo esc_html( $log['attack_type'] ); ?>
                            </span>
                        </td>
                        <td>
                            <span class="nexura-badge safe">
                                <?php echo esc_html( $log['action_taken'] ); ?>
                            </span>
                        </td>
                        <td style="color: var(--nexura-text-muted); font-size: 12px;">
                            <?php echo esc_html( wp_date( get_option('date_format') . ' ' . get_option('time_format'), strtotime( $log['timestamp'] ) ) ); ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <!-- Smart JavaScript for Country Detection without slowing down backend -->
        <script>
        document.addEventListener('DOMContentLoaded', function() {
            const countryCells = document.querySelectorAll('.nexura-country-cell');
            const uniqueIps = new Set();
            
            countryCells.forEach(cell => {
                const ip = cell.getAttribute('data-ip');
                if (ip && cell.textContent.trim() === 'Detecting...') {
                    uniqueIps.add(ip);
                }
            });

            if (uniqueIps.size > 0) {
                // Batch request to ip-api for better performance
                const ipArray = Array.from(uniqueIps);
                const reqBody = ipArray.map(ip => { return { query: ip, fields: "country,countryCode" } });

                fetch('http://ip-api.com/batch', {
                    method: 'POST',
                    body: JSON.stringify(reqBody)
                })
                .then(res => res.json())
                .then(data => {
                    const countryMap = {};
                    data.forEach(result => {
                        if (result.status === 'success') {
                            countryMap[result.query] = {
                                name: result.country,
                                code: result.countryCode.toLowerCase()
                            };
                        }
                    });

                    countryCells.forEach(cell => {
                        const ip = cell.getAttribute('data-ip');
                        if (countryMap[ip]) {
                            const flagUrl = 'https://flagcdn.com/16x12/' + countryMap[ip].code + '.png';
                            cell.innerHTML = '<img src="' + flagUrl + '" alt="' + countryMap[ip].code + '" style="margin-right: 6px; vertical-align: middle;"> ' + countryMap[ip].name;
                        } else if (cell.textContent.trim() === 'Detecting...') {
                            cell.innerHTML = '<span style="color: var(--nexura-text-muted);">Unknown</span>';
                        }
                    });
                })
                .catch(err => {
                    countryCells.forEach(cell => {
                        if (cell.textContent.trim() === 'Detecting...') {
                            cell.innerHTML = '<span style="color: var(--nexura-text-muted);">Unknown</span>';
                        }
                    });
                });
            }
        });
        </script>
    <?php else : ?>
        <div style="text-align: center; padding: 40px 0; color: var(--nexura-text-muted);">
            <div style="margin-bottom: 12px; display: flex; justify-content: center;"><svg width="48" height="48" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="color:#10b981;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg></div>
            <p style="font-size: 15px; font-weight: 600;">No attacks blocked recently.</p>
            <p style="font-size: 13px;">Your site traffic is clean.</p>
        </div>
    <?php endif; ?>
</div>
