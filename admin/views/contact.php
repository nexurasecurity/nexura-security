<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}
?>


    

    <div class="nexura-card nexura-fade-in" style="max-width: 800px; margin: 0 auto; text-align: center; padding: 40px 20px;">
        <h2 style="font-size: 24px; margin-bottom: 10px; color: var(--nexura-text);">
            <?php esc_html_e( 'Contact Support', 'nexura-security' ); ?>
        </h2>
        <p style="color: var(--nexura-text-secondary); font-size: 16px; line-height: 1.6; margin-bottom: 30px;">
            <?php esc_html_e( 'Need help with Nexura Security? Our support team is here to assist you with any questions or technical issues you might be facing.', 'nexura-security' ); ?>
        </p>

        <div style="background: var(--nexura-bg-darker); border-radius: 12px; padding: 30px; text-align: left; margin-bottom: 30px; border: 1px solid var(--nexura-border);">
            <h3 style="margin-top: 0; color: var(--nexura-primary); margin-bottom: 15px;">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 5px;"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline></svg>
                <?php esc_html_e( 'Email Support', 'nexura-security' ); ?>
            </h3>
            <p style="color: var(--nexura-text); margin-bottom: 20px;">
                <?php esc_html_e( 'For direct assistance, please reach out to us at:', 'nexura-security' ); ?>
                <br>
                <strong><a href="mailto:support@nexurasecurity.com" style="color: var(--nexura-primary); text-decoration: none;">support@nexurasecurity.com</a></strong>
            </p>
            <p style="color: var(--nexura-text-muted); font-size: 13px;">
                <em><?php esc_html_e( 'Please include your site URL, WordPress version, and Nexura Security version when emailing us so we can assist you faster.', 'nexura-security' ); ?></em>
            </p>
        </div>
        
        <div style="background: var(--nexura-bg-darker); border-radius: 12px; padding: 30px; text-align: left; margin-bottom: 30px; border: 1px solid var(--nexura-border); display: flex; align-items: center; justify-content: space-between;">
            <div>
                <h3 style="margin-top: 0; color: var(--nexura-primary); margin-bottom: 15px;">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 5px; color: #25D366;"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"></path></svg>
                    <?php esc_html_e( 'WhatsApp Support', 'nexura-security' ); ?>
                </h3>
                <p style="color: var(--nexura-text); margin-bottom: 5px;">
                    <?php esc_html_e( 'For urgent issues, chat directly with our technical team via WhatsApp.', 'nexura-security' ); ?>
                </p>
                <p style="color: var(--nexura-text-muted); font-size: 13px; margin-bottom: 0;">
                    <em><?php esc_html_e( 'Available during business hours (GMT+6).', 'nexura-security' ); ?></em>
                </p>
            </div>
            <div>
                <a href="https://wa.me/8801732593040" target="_blank" class="button button-primary" style="background: #25D366; border: none; font-weight: 500; display: inline-flex; align-items: center; gap: 8px;">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"></path></svg>
                    <?php esc_html_e( 'Chat on WhatsApp', 'nexura-security' ); ?>
                </a>
            </div>
        </div>

        <div style="background: var(--nexura-bg-darker); border-radius: 12px; padding: 30px; text-align: left; border: 1px solid var(--nexura-border);">
            <h3 style="margin-top: 0; color: var(--nexura-primary); margin-bottom: 15px;">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 5px;"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"></path><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"></path></svg>
                <?php esc_html_e( 'Documentation', 'nexura-security' ); ?>
            </h3>
            <p style="color: var(--nexura-text); margin-bottom: 20px;">
                <?php esc_html_e( 'Check out our comprehensive documentation for guides, tutorials, and frequently asked questions.', 'nexura-security' ); ?>
            </p>
            <a href="https://nexurasecurity.com/help" target="_blank" class="button button-secondary" style="border-color: var(--nexura-border); color: var(--nexura-text); background: transparent;">
                <?php esc_html_e( 'View Documentation', 'nexura-security' ); ?> &rarr;
            </a>
        </div>
    </div>

