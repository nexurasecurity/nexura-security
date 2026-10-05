<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}
?>
<!-- Header Section -->
<div class="nexura-header nexura-fade-in">
    <h1><?php esc_html_e( 'Reinfection Guard', 'nexura-security' ); ?></h1>
    <p><?php esc_html_e( 'Find the root cause of returning malware, identify persistence vectors, and eliminate reinfection mechanisms.', 'nexura-security' ); ?></p>
</div>

<!-- Investigation Control Card -->
<div class="nexura-card nexura-fade-in" style="margin-bottom: 24px;">
    <h2>
        <span class="nexura-card-icon">
            <svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0zM10 7v3m0 0v3m0-3h3m-3 0H7"></path>
            </svg>
        </span>
        <?php esc_html_e( 'Start Investigation', 'nexura-security' ); ?>
    </h2>
    <p style="color: var(--nexura-text-secondary); margin-bottom: 16px; font-size: 13.5px;">
        <?php esc_html_e( 'Enter a specific malicious or returning file path to trace how it was created, or leave empty to run a comprehensive site-wide persistence audit.', 'nexura-security' ); ?>
    </p>
    
    <div style="display: flex; gap: 12px; align-items: center; flex-wrap: wrap;">
        <div style="position: relative; flex: 1; max-width: 480px;">
            <input type="text" id="nexura_investigation_target" placeholder="e.g. wp-content/uploads/cache.php (or empty for full audit)" style="width: 100%; height: 42px; padding: 10px 14px; font-size: 13.5px;">
        </div>
        <button id="nexura_start_investigation" class="nexura-btn nexura-btn-primary" style="height: 42px; padding: 0 24px;">
            <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
            </svg>
            <?php esc_html_e( 'Investigate Root Cause', 'nexura-security' ); ?>
        </button>
        <button id="nexura_clear_investigation" class="nexura-btn nexura-btn-secondary" style="height: 42px; padding: 0 18px; display: none;">
            <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
            </svg>
            <?php esc_html_e( 'Clear Results', 'nexura-security' ); ?>
        </button>
    </div>
    
    <div id="nexura_investigation_status" style="margin-top: 18px; display: none; align-items: center; gap: 12px;">
        <div class="nexura-progress" style="flex: 1; margin: 0; max-width: 320px;">
            <div id="nexura_investigation_progress_bar" class="nexura-progress-bar" style="width: 25%;"></div>
        </div>
        <span class="nexura-live-dot green"></span>
        <span id="nexura_investigation_status_text" style="color: var(--nexura-accent-light); font-size: 13px; font-weight: 500;">
            <?php esc_html_e( 'Initializing investigation...', 'nexura-security' ); ?>
        </span>
    </div>
</div>

<!-- Investigation Output Container -->
<div id="nexura_reinfection_output" style="width: 100%;">
    <div id="nexura_reinfection_graph_container" style="width: 100%;">
        <div class="nexura-card nexura-fade-in" style="animation-delay: 0.1s;">
            <div class="nexura-rg-empty-state">
                <svg width="48" height="48" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="color: var(--nexura-text-muted); margin-bottom: 12px; opacity: 0.6;">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                </svg>
                <p style="color: var(--nexura-text-muted); font-size: 14px; margin: 0;">
                    <?php esc_html_e( 'No investigation results yet. Click "Investigate Root Cause" to start scanning.', 'nexura-security' ); ?>
                </p>
            </div>
        </div>
    </div>
</div>



