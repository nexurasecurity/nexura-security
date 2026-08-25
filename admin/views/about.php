<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="nexura-card nexura-fade-in">
    <div style="text-align: center; padding: 20px 0 30px;">
         <div class="nexura-about-logo" ><img src="<?php echo esc_url( NEXURA_PLUGIN_URL . 'admin/img/icon.png' ); ?>" alt="Nexura Security Logo" ></div>
        <h1 style="font-size: 28px; color: var(--nexura-text); margin: 0 0 10px 0; font-weight: 700;">Nexura Security</h1>
        <p style="color: var(--nexura-text-secondary); font-size: 16px; max-width: 600px; margin: 0 auto;">
            Enterprise-level WordPress protection, malware scanning, and vulnerability auditing. Built for performance and reliability.
        </p>
    </div>

    <div class="nexura-grid-2" style="margin-top: 30px; gap: 30px;">
        <!-- Left Column: What It Does -->
        <div style="background: rgba(15, 23, 42, 0.4); padding: 25px; border-radius: 10px; border: 1px solid var(--nexura-border);">
            <h2 style="font-size: 20px; margin-top: 0; margin-bottom: 20px; color: #38bdf8; display: flex; align-items: center; gap: 10px;">
                <span ><img src="<?php echo esc_url( NEXURA_PLUGIN_URL . 'admin/img/icon.png' ); ?>" alt="Nexura Security Logo"  style="width: 24px; object-fit: contain;" ></span> 360° Website Protection
            </h2>
            <ul style="color: var(--nexura-text-secondary); line-height: 1.8; font-size: 14.5px; list-style-type: none; padding-left: 0; margin: 0;">
                <li style="margin-bottom: 12px; display: flex; gap: 10px;">
                    <span style="color: #10b981;"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg></span> 
                    <span><strong>Deep Malware Eradication:</strong> Asynchronously scans all core, plugin, and theme files without timing out or crashing your server.</span>
                </li>
                <li style="margin-bottom: 12px; display: flex; gap: 10px;">
                    <span style="color: #10b981;"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg></span> 
                    <span><strong>Real-Time File Integrity (FIM):</strong> Creates a strict cryptographic baseline of your files to detect unauthorized hacker modifications instantly.</span>
                </li>
                <li style="margin-bottom: 12px; display: flex; gap: 10px;">
                    <span style="color: #10b981;"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg></span> 
                    <span><strong>Google Safe Browsing Sync:</strong> Integrates directly with Google's API to ensure your domain is never blacklisted for phishing.</span>
                </li>
                <li style="margin-bottom: 12px; display: flex; gap: 10px;">
                    <span style="color: #10b981;"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg></span> 
                    <span><strong>Smart Brute-Force Shield:</strong> Automatically blocks malicious IP addresses after failed login attempts, keeping hackers out.</span>
                </li>
                <li style="display: flex; gap: 10px;">
                    <span style="color: #10b981;"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg></span> 
                    <span><strong>Automated Vulnerability Audits:</strong> Proactively cross-references your installed themes and plugins against known CVE databases.</span>
                </li>
            </ul>
        </div>
        
        <!-- Right Column: Why We Are Better -->
        <div style="background: rgba(15, 23, 42, 0.4); padding: 25px; border-radius: 10px; border: 1px solid var(--nexura-border);">
            <h2 style="font-size: 20px; margin-top: 0; margin-bottom: 20px; color: #ec4899; display: flex; align-items: center; gap: 10px;">
                <span><svg width="24" height="24" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg></span> Why Nexura is Better
            </h2>
            
            <div style="margin-bottom: 16px;">
                <h4 style="color: #f3f4f6; margin: 0 0 5px 0; font-size: 15px;">1. Designed for low database overhead</h4>
                <p style="color: var(--nexura-text-secondary); line-height: 1.6; font-size: 14px; margin: 0;">
                    Unlike traditional security plugins that store millions of logs in your WordPress database (making your site extremely slow), Nexura offloads logs to the filesystem or <strong>Cloudflare D1</strong>. Your site remains lightning fast.
                </p>
            </div>

            <div style="margin-bottom: 16px;">
                <h4 style="color: #f3f4f6; margin: 0 0 5px 0; font-size: 15px;">2. No Server Crashes During Scans</h4>
                <p style="color: var(--nexura-text-secondary); line-height: 1.6; font-size: 14px; margin: 0;">
                    Other plugins crash large sites because they scan everything in a single PHP execution. Nexura uses an advanced <strong>Micro-Batching Architecture</strong>. We break heavy tasks into small chunks, ensuring low performance overhead.
                </p>
            </div>

            <div>
                <h4 style="color: #f3f4f6; margin: 0 0 5px 0; font-size: 15px;">3. Advanced, Yet Lightweight</h4>
                <p style="color: var(--nexura-text-secondary); line-height: 1.6; font-size: 14px; margin: 0;">
                    Nexura is built specifically to provide the highest level of security without the clunky, resource-heavy features you don't need. It's security that actually scales with your traffic.
                </p>
            </div>
        </div>
    </div>
</div>

<?php if ( ! nexura_is_pro() ) : ?>
<div class="nexura-card nexura-fade-in" style="margin-top: 30px; border: 1px solid rgba(236, 72, 153, 0.5); background: linear-gradient(145deg, rgba(236, 72, 153, 0.05) 0%, rgba(15, 23, 42, 0.4) 100%);">
    <div style="text-align: center; margin-bottom: 25px;">
        <h2 style="font-size: 24px; color: #ec4899; margin: 0 0 10px 0;">👑 Why Upgrade to Nexura Pro?</h2>
        <p style="color: var(--nexura-text-secondary); font-size: 15px; max-width: 650px; margin: 0 auto;">
            The free version provides exceptional basic security. However, if you are running a serious business, eCommerce store, or high-traffic website, Nexura Pro provides the ultimate peace of mind with robust automated protection.
        </p>
    </div>

    <div class="nexura-grid-2" style="gap: 20px;">
        <div style="background: rgba(15, 23, 42, 0.6); padding: 20px; border-radius: 8px;">
            <h4 style="color: #f3f4f6; margin: 0 0 10px 0; font-size: 15px; display: flex; align-items: center; gap: 8px;"><span style="color:#ec4899;"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 3v4M3 5h4M6 17v4m-2-2h4m5-16l2.286 6.857L21 12l-5.714 2.143L13 21l-2.286-6.857L5 12l5.714-2.143z"></path></svg></span> 1-Click Auto Malware Cleanup</h4>
            <p style="color: var(--nexura-text-secondary); font-size: 13px; margin: 0; line-height: 1.6;">Don't just detect malware—eradicate it. Our Pro engine automatically quarantines and cleans infected files with a single click.</p>
        </div>
        <div style="background: rgba(15, 23, 42, 0.6); padding: 20px; border-radius: 8px;">
            <h4 style="color: #f3f4f6; margin: 0 0 10px 0; font-size: 15px; display: flex; align-items: center; gap: 8px;"><span style="color:#ec4899;"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z"></path></svg></span> Cloudflare D1 Integration</h4>
            <p style="color: var(--nexura-text-secondary); font-size: 13px; margin: 0; line-height: 1.6;">Offload 100% of your activity logs to Cloudflare's Edge Database. Keep your local WordPress database completely empty and fast.</p>
        </div>
        <div style="background: rgba(15, 23, 42, 0.6); padding: 20px; border-radius: 8px;">
            <h4 style="color: #f3f4f6; margin: 0 0 10px 0; font-size: 15px; display: flex; align-items: center; gap: 8px;"><span style="color:#ec4899;"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 3h2l.4 2M7 13h10l4-8H5.4M7 13L5.4 5M7 13l-2.293 2.293c-.63.63-.184 1.707.707 1.707H17m0 0a2 2 0 100 4 2 2 0 000-4zm-8 2a2 2 0 11-4 0 2 2 0 014 0z"></path></svg></span> WooCommerce Protection</h4>
            <p style="color: var(--nexura-text-secondary); font-size: 13px; margin: 0; line-height: 1.6;">Stop card-testing attacks and fake orders dead in their tracks. We specifically protect WooCommerce checkouts and accounts.</p>
        </div>
        <div style="background: rgba(15, 23, 42, 0.6); padding: 20px; border-radius: 8px;">
            <h4 style="color: #f3f4f6; margin: 0 0 10px 0; font-size: 15px; display: flex; align-items: center; gap: 8px;"><span style="color:#ec4899;"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg></span> Instant Core File Rollback</h4>
            <p style="color: var(--nexura-text-secondary); font-size: 13px; margin: 0; line-height: 1.6;">If a hacker modifies your WordPress core files, Pro can instantly restore them to their pristine original state in seconds.</p>
        </div>
        <div style="background: rgba(15, 23, 42, 0.6); padding: 20px; border-radius: 8px;">
            <h4 style="color: #f3f4f6; margin: 0 0 10px 0; font-size: 15px; display: flex; align-items: center; gap: 8px;"><span style="color:#ec4899;"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg></span> Endpoint WAF (Firewall)</h4>
            <p style="color: var(--nexura-text-secondary); font-size: 13px; margin: 0; line-height: 1.6;">Blocks SQLi, XSS, and bot attacks before WordPress even loads using advanced pre-boot firewall rules.</p>
        </div>
        <div style="background: rgba(15, 23, 42, 0.6); padding: 20px; border-radius: 8px;">
            <h4 style="color: #f3f4f6; margin: 0 0 10px 0; font-size: 15px; display: flex; align-items: center; gap: 8px;"><span style="color:#ec4899;"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0zM10 7v3m0 0v3m0-3h3m-3 0H7"></path></svg></span> Tokenizer Smart Scanner</h4>
            <p style="color: var(--nexura-text-secondary); font-size: 13px; margin: 0; line-height: 1.6;">Detects complex zero-day backdoors and obfuscated malware that traditional regex scanners miss.</p>
        </div>
        <div style="background: rgba(15, 23, 42, 0.6); padding: 20px; border-radius: 8px;">
            <h4 style="color: #f3f4f6; margin: 0 0 10px 0; font-size: 15px; display: flex; align-items: center; gap: 8px;"><span style="color:#ec4899;"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg></span> Enterprise Storage Scanner</h4>
            <p style="color: var(--nexura-text-secondary); font-size: 13px; margin: 0; line-height: 1.6;">Safely detect and remove unused images, PDFs, and orphan files from your uploads directory to save disk space and improve backup speed.</p>
        </div>
        <div style="background: rgba(15, 23, 42, 0.6); padding: 20px; border-radius: 8px;">
            <h4 style="color: #f3f4f6; margin: 0 0 10px 0; font-size: 15px; display: flex; align-items: center; gap: 8px;"><span style="color:#ec4899;"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg></span> Database Optimizer</h4>
            <p style="color: var(--nexura-text-secondary); font-size: 13px; margin: 0; line-height: 1.6;">Clean up post revisions, transients, orphaned metadata, and optimize database tables for a faster website.</p>
        </div>
    </div>

    <div style="text-align: center; margin-top: 30px;">
        <a href="<?php echo esc_url( function_exists('nexurasec_fs') ? (nexurasec_fs()->is_pricing_page_visible() ? nexurasec_fs()->get_upgrade_url() : nexurasec_fs()->get_account_url()) : '' ); ?>" class="button button-primary" style="background: #ec4899; border-color: #ec4899; padding: 5px 30px; font-size: 16px; font-weight: bold; border-radius: 4px; box-shadow: 0 4px 15px rgba(236, 72, 153, 0.3);">
            Upgrade to Nexura Pro Now &rarr;
        </a>
    </div>
</div>

<div class="nexura-card nexura-fade-in" style="animation-delay: 0.15s; text-align: center; margin-top: 30px; padding: 40px 20px; background: linear-gradient(145deg, rgba(15, 23, 42, 0.8) 0%, rgba(30, 41, 59, 0.4) 100%);">
    <h2 style="font-size: 24px; margin-bottom: 15px;">Support the Development</h2>
    <p style="color: var(--nexura-text-secondary); max-width: 600px; margin: 0 auto 25px auto; line-height: 1.6;">
        Nexura Security is an open-source project dedicated to keeping WordPress safe for everyone. If this plugin has saved you time or protected your site, please consider supporting the author!
    <?php
    // phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
    $NEXURA_site_domain = wp_parse_url( site_url(), PHP_URL_HOST );
    $NEXURA_wa_message = urlencode( "Hello, I need support for my site: " . $NEXURA_site_domain );
    $NEXURA_wa_url = "https://wa.me/8801732593040?text=" . $NEXURA_wa_message;
    // phpcs:enable
    ?>
    <div style="display: flex; justify-content: center; gap: 15px; flex-wrap: wrap;">
        <!-- bKash Donate -->
        <div style="display: inline-flex; flex-direction: column; justify-content: center; background: linear-gradient(135deg, #e2136e 0%, #b80d56 100%); color: white; padding: 10px 25px; border-radius: 6px; box-shadow: 0 4px 6px rgba(226, 19, 110, 0.2);">
            <div style="font-size: 12px; font-weight: 600; margin-bottom: 2px;">☕ Donate via bKash (Personal)</div>
            <div style="font-size: 16px; font-weight: 700; letter-spacing: 1px;">01732593040</div>
        </div>

        <!-- WhatsApp -->
        <a href="<?php echo esc_url( $NEXURA_wa_url ); ?>" target="_blank" style="display: inline-flex; align-items: center; gap: 8px; background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: white; text-decoration: none; padding: 12px 30px; border-radius: 6px; font-size: 16px; font-weight: 600; box-shadow: 0 4px 6px rgba(16, 185, 129, 0.2); transition: transform 0.2s;">
            <span><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"></path></svg></span> Chat on WhatsApp
        </a>
    </div>
    
    <p style="margin-top: 20px; font-size: 13px; color: var(--nexura-text-muted);">
        Created by <strong>Prokash Sarker</strong>. <br>
        Thank you for helping keep the web secure!
    </p>
</div>
<?php endif; ?>
