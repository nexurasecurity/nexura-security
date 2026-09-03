<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="nexura-card nexura-fade-in">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; flex-wrap: wrap; gap: 15px;">
        <div>
            <h2 style="margin: 0;"><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg></span> <?php esc_html_e( 'Issues Detected', 'nexura-security' ); ?></h2>
            <p style="color: var(--nexura-text-muted); margin: 5px 0 0 0;"><?php esc_html_e( 'Review, edit, or delete files that were flagged during the malware scan.', 'nexura-security' ); ?></p>
            <div style="margin-top: 10px; padding: 10px 15px; background: rgba(34, 113, 177, 0.05); border-left: 4px solid #2271b1; border-radius: 4px; font-size: 13px;">
                <strong><svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="vertical-align: text-bottom; color: #2271b1; margin-right: 2px;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg> <?php esc_html_e( 'Safety Notice:', 'nexura-security' ); ?></strong>
                <?php esc_html_e( 'To prevent breaking your site, highly complex malware will NOT be auto-cleaned. If a file cannot be auto-cleaned safely, it will be marked for manual review.', 'nexura-security' ); ?>
            </div>
        </div>
        
        <?php do_action( 'nexura_issues_detected_header_actions' ); ?>
    </div>
    

    <div id="nexura-issues-page" style="display: none;"></div> <!-- Hidden marker for JS -->

    <div id="nexura-scan-results" style="margin-top: 20px;">
        <div style="padding: 20px; text-align: center; color: var(--nexura-text-muted);">
            <div class="nexura-spinner" style="display: inline-block; margin-bottom: 10px;"></div>
            <p>Loading detected issues...</p>
        </div>
    </div>
</div>
