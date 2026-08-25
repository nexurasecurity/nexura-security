<?php
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
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

<div class="nexura-card nexura-fade-in" style="animation-delay: 0.3s;">
    <h2><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg></span> <?php esc_html_e( 'Change History', 'nexura-security' ); ?></h2>
    <?php
    $history = get_option( 'NEXURA_fim_history', [] );
    if ( empty( $history ) ) {
        echo '<p style="color: var(--nexura-text-muted);">' . esc_html__( 'No changes detected yet.', 'nexura-security' ) . '</p>';
    } else {
        echo '<table class="wp-list-table widefat fixed striped">';
        echo '<thead><tr>';
        echo '<th>' . esc_html__( 'Time', 'nexura-security' ) . '</th>';
        echo '<th>' . esc_html__( 'Added Files', 'nexura-security' ) . '</th>';
        echo '<th>' . esc_html__( 'Modified Files', 'nexura-security' ) . '</th>';
        echo '<th>' . esc_html__( 'Deleted Files', 'nexura-security' ) . '</th>';
        echo '</tr></thead><tbody>';
        foreach ( $history as $entry ) {
            echo '<tr>';
            echo '<td>' . esc_html( $entry['time'] ) . '</td>';
            echo '<td style="color: #10b981;">+' . intval( $entry['added'] ) . '</td>';
            echo '<td style="color: #f59e0b;">~' . intval( $entry['modified'] ) . '</td>';
            echo '<td style="color: #ef4444;">-' . intval( $entry['deleted'] ) . '</td>';
            echo '</tr>';
        }
        echo '</tbody></table>';
    }
    ?>
</div>
