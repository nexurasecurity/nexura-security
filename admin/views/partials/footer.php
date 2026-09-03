<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
        </main>
    </div><!-- .nexura-dashboard-layout -->
    
    <!-- File Editor Modal (Global) -->
    <div id="nexura-file-editor-modal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.6); z-index: 9999; align-items: center; justify-content: center;">
        <div style="background: var(--nexura-bg); padding: 20px; border-radius: 8px; width: 80%; max-width: 800px; box-shadow: 0 4px 20px rgba(0,0,0,0.3);">
            <h3 style="margin-top: 0; color: var(--nexura-text); display: flex; justify-content: space-between;">
                <span>✏️ Edit File: <code id="nexura-editor-filename" style="color: var(--nexura-accent);"></code></span>
                <button type="button" class="nexura-close-editor" style="background: none; border: none; color: var(--nexura-text-muted); cursor: pointer; font-size: 20px;">&times;</button>
            </h3>
            <textarea id="nexura-editor-content" style="width: 100%; height: 400px; font-family: monospace; padding: 10px; background: #1e1e1e; color: #d4d4d4; border: 1px solid var(--nexura-border);"></textarea>
            <input type="hidden" id="nexura-editor-filepath" value="">
            <div style="margin-top: 15px; display: flex; gap: 10px; justify-content: flex-end;">
                <button type="button" class="nexura-btn nexura-btn-secondary nexura-close-editor">Cancel</button>
                <button type="button" id="nexura-save-file" class="nexura-btn nexura-btn-primary">Save Changes</button>
            </div>
        </div>
    </div>
    
    <?php if ( ! nexura_is_pro() ) : ?>
    <!-- Pro Upgrade Modal (Premium Redesign) -->
    <div id="nexura-pro-upgrade-modal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(2, 6, 23, 0.7); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); z-index: 99999; align-items: center; justify-content: center; animation: nexuraModalFadeIn 0.4s cubic-bezier(0.16, 1, 0.3, 1);">


        <div class="nexura-premium-modal">
            <div class="nexura-premium-modal-inner">
                <button type="button" onclick="document.getElementById('nexura-pro-upgrade-modal').style.display='none';" style="position: absolute; top: 15px; right: 15px; background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.15); color: #94a3b8; width: 32px; height: 32px; border-radius: 50%; font-size: 18px; cursor: pointer; display: flex; align-items: center; justify-content: center; z-index: 10; transition: all 0.2s;" onmouseover="this.style.background='rgba(255,255,255,0.2)';this.style.color='#f8fafc';" onmouseout="this.style.background='rgba(255,255,255,0.1)';this.style.color='#94a3b8';">&times;</button>
                <div class="nexura-premium-icon-wrap">
                    ✨
                </div>
                <h3 class="nexura-premium-title">
                    <?php esc_html_e( 'Pro-Only Feature', 'nexura-security' ); ?>
                </h3>
                <p class="nexura-premium-text">
                    <?php esc_html_e( 'This feature is available in the separate Nexura Pro add-on plugin. Upgrade to access advanced automation, real-time analytics, and deep vulnerability audits.', 'nexura-security' ); ?>
                </p>
                <a href="<?php echo esc_url( function_exists('nsp_fs') ? (nsp_fs()->is_pricing_page_visible() ? nsp_fs()->get_upgrade_url() : nsp_fs()->get_account_url()) : '' ); ?>" class="nexura-premium-btn">
                    <?php esc_html_e( 'Upgrade to Pro Now', 'nexura-security' ); ?>
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
                </a>
            </div>
        </div>
    </div>
    <?php endif; ?>
</div><!-- .nexura-wrap -->
