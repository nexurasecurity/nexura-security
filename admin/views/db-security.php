<?php
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$db_scanner = new \Nexura_Security\DB_Scanner();
$findings = $db_scanner->run_advanced_db_scan();
?>

<div class="nexura-card nexura-fade-in">
    <h2><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"></path></svg></span> <?php esc_html_e( 'Database Security Audit', 'nexura-security' ); ?></h2>
    
    <p class="description" style="margin-bottom: 20px;">
        <?php esc_html_e( 'Scans the WordPress database for ghost administrators, malicious options, and injected scripts inside posts/pages.', 'nexura-security' ); ?>
    </p>

    <div style="background: var(--nexura-bg-card); border-radius: 8px; border: 1px solid var(--nexura-border); overflow: hidden;">
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th scope="col" style="width: 25%;"><?php esc_html_e( 'Issue / Pattern', 'nexura-security' ); ?></th>
                    <th scope="col" style="width: 15%;"><?php esc_html_e( 'Risk Level', 'nexura-security' ); ?></th>
                    <th scope="col" style="width: 60%;"><?php esc_html_e( 'Description', 'nexura-security' ); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php
                if ( empty( $findings ) ) {
                    ?>
                    <tr>
                        <td colspan="3" style="text-align: center; padding: 20px; color: #10b981; font-weight: bold;">
                            <span style="display: inline-flex; align-items: center; justify-content: center; gap: 8px;"><svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg> <?php esc_html_e( 'No database security issues found! Your database looks clean.', 'nexura-security' ); ?></span>
                        </td>
                    </tr>
                    <?php
                } else {
                    foreach ( $findings as $finding ) {
                        $risk_color = '#f59e0b'; // Medium (Orange)
                        if ( $finding['risk'] === 'High' ) {
                            $risk_color = '#ef4444'; // High (Red)
                        } elseif ( $finding['risk'] === 'Critical' ) {
                            $risk_color = '#991b1b'; // Critical (Dark Red)
                        }

                        $badge = sprintf( '<span style="display:inline-block; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; background: %s; color: #fff;">%s</span>', $risk_color, strtoupper( esc_html( $finding['risk'] ) ) );
                        ?>
                        <tr>
                            <td><strong><?php echo esc_html( $finding['pattern'] ); ?></strong></td>
                            <td><?php echo $badge; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></td>
                            <td><?php echo esc_html( $finding['description'] ); ?></td>
                        </tr>
                        <?php
                    }
                }
                ?>
            </tbody>
        </table>
    </div>
</div>
