<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<?php
$NEXURA_plan = function_exists('nexura_is_pro') && nexura_is_pro() ? 'pro' : 'free';
?>

<div class="nexura-header" style="margin-bottom: 20px;">
    <h1>File Integrity Monitoring (FIM)</h1>
    <p>Monitor your core files, plugins, and themes for unauthorized changes.</p>
</div>

<?php do_action( 'nexura_pro_auto_heal_ui' ); ?>

<div class="nexura-card nexura-fade-in">
    <h2><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg></span> <?php esc_html_e( 'Baseline Generation', 'nexura-security' ); ?></h2>
    <p><?php esc_html_e( 'Generate a baseline of your core files, plugins, and themes to monitor for unauthorized changes.', 'nexura-security' ); ?></p>
    <div style="display: flex; gap: 10px;">
        <button id="nexura-generate-baseline" class="nexura-btn nexura-btn-secondary"><?php esc_html_e( 'Generate Baseline', 'nexura-security' ); ?></button>
        <button id="nexura-check-integrity" class="nexura-btn nexura-btn-primary"><?php esc_html_e( 'Check Integrity', 'nexura-security' ); ?></button>
    </div>
</div>

<div class="nexura-card nexura-fade-in" style="animation-delay: 0.15s;">
    <h2><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg></span> <?php esc_html_e( 'Integrity Results', 'nexura-security' ); ?></h2>
    <div id="nexura-fim-results">
        <p style="color: var(--nexura-text-muted);"><?php esc_html_e( 'No recent checks.', 'nexura-security' ); ?></p>
    </div>
</div>
