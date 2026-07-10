<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="nexura-card nexura-fade-in">
    <h2><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg></span> <?php esc_html_e( 'Site Status', 'nexura-security' ); ?></h2>
    <p><?php esc_html_e( 'Check your site against the Google Safe Browsing API to see if it is flagged for malware or phishing.', 'nexura-security' ); ?></p>
    <button id="nexura-check-gsb" class="nexura-btn nexura-btn-primary"><?php esc_html_e( 'Check Site Status', 'nexura-security' ); ?></button>
    <div id="nexura-gsb-results" style="margin-top: 15px;"></div>
</div>

<div class="nexura-card nexura-fade-in" style="animation-delay: 0.15s;">
    <h2><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path></svg></span> <?php esc_html_e( 'Remediation Workflow', 'nexura-security' ); ?></h2>
    <ol style="color: var(--nexura-text-secondary); line-height: 2;">
        <li><?php esc_html_e( 'Review the Malware Scan tab and quarantine any detected suspicious files.', 'nexura-security' ); ?></li>
        <li><?php esc_html_e( 'Check the File Integrity Monitoring tab for unauthorized file modifications.', 'nexura-security' ); ?></li>
        <li><?php esc_html_e( 'Ensure all plugins and themes are updated via the Vulnerability Audit tab.', 'nexura-security' ); ?></li>
        <li><?php esc_html_e( 'Once the site is clean, request a review in Google Search Console.', 'nexura-security' ); ?></li>
    </ol>
</div>
