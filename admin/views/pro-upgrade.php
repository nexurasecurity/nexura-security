<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>

<div class="nexura-pro-wrapper">
    <div class="nexura-pro-card">
        
        <!-- SVG Definitions for Gradients -->
        <svg style="width:0;height:0;position:absolute;" aria-hidden="true" focusable="false">
          <linearGradient id="proGradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#f59e0b" />
            <stop offset="100%" stop-color="#ec4899" />
          </linearGradient>
        </svg>

        <div class="nexura-pro-icon-container">
            <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
                <!-- Star inside shield -->
                <path d="M12 7.5l1.45 3.4 3.65.31-2.77 2.41.83 3.58L12 15.34l-3.16 1.86.83-3.58-2.77-2.41 3.65-.31L12 7.5z"/>
            </svg>
        </div>
        
        <h2 class="nexura-pro-title">
            <?php esc_html_e( 'Unlock Premium Security', 'nexura-security' ); ?>
        </h2>
        
        <p class="nexura-pro-desc">
            <?php esc_html_e( 'You have discovered a premium feature! Upgrade to Nexura Pro to instantly access elite security tools designed to protect your enterprise.', 'nexura-security' ); ?>
        </p>

        <div class="nexura-pro-features">
            <div class="nexura-pro-feature">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                Advanced Malware Scans
            </div>
            <div class="nexura-pro-feature">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                Instant File Rollback
            </div>
            <div class="nexura-pro-feature">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                Vulnerability Audits
            </div>
            <div class="nexura-pro-feature">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                Automated Malware Cleanup
            </div>
        </div>
        
        <a href="<?php echo esc_url( function_exists('nexurasec_fs') ? nexurasec_fs()->get_upgrade_url() : 'https://nexurasecurity.com/pricing' ); ?>" class="nexura-upgrade-btn">
            <?php esc_html_e( 'Upgrade to Pro Now', 'nexura-security' ); ?>
            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 5l7 7m0 0l-7 7m7-7H3"></path></svg>
        </a>
    </div>
</div>
