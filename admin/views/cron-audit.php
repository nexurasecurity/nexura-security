<?php
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$cron_audit = new \Nexura_Security\Cron_Audit();
$all_results = $cron_audit->get_audit_results();

// Pagination logic
$per_page     = 15;
$current_page = isset( $_GET['paged'] ) ? max( 1, intval( $_GET['paged'] ) ) : 1;
$total_items  = count( $all_results );
$total_pages  = ceil( $total_items / $per_page );
$results      = array_slice( $all_results, ( $current_page - 1 ) * $per_page, $per_page );
?>

<div class="nexura-card nexura-fade-in">
    <h2><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg></span> <?php esc_html_e( 'WP-Cron Audit', 'nexura-security' ); ?></h2>
    
    <p class="description" style="margin-bottom: 20px;">
        <?php esc_html_e( 'Analyzes all scheduled background tasks (WP-Cron) to detect injected malware, unknown tasks, or suspicious payloads.', 'nexura-security' ); ?>
    </p>

    <div style="background: var(--nexura-bg-card); border-radius: 8px; border: 1px solid var(--nexura-border); overflow: hidden;">
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th scope="col" style="width: 25%;"><?php esc_html_e( 'Hook Name', 'nexura-security' ); ?></th>
                    <th scope="col" style="width: 15%;"><?php esc_html_e( 'Next Run', 'nexura-security' ); ?></th>
                    <th scope="col" style="width: 15%;"><?php esc_html_e( 'Schedule', 'nexura-security' ); ?></th>
                    <th scope="col" style="width: 15%;"><?php esc_html_e( 'Status', 'nexura-security' ); ?></th>
                    <th scope="col" style="width: 30%;"><?php esc_html_e( 'Details', 'nexura-security' ); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php
                if ( empty( $results ) ) {
                    ?>
                    <tr>
                        <td colspan="5" style="text-align: center; padding: 20px; color: var(--nexura-text-muted);">
                            <?php esc_html_e( 'No scheduled crons found.', 'nexura-security' ); ?>
                        </td>
                    </tr>
                    <?php
                } else {
                    foreach ( $results as $cron ) {
                        $status_html = '';
                        if ( $cron['status'] === 'malicious' ) {
                            $status_html = '<span style="color: #ef4444; font-weight: 600; display: inline-flex; align-items: center; gap: 6px;"><svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg> ' . __( 'Suspicious', 'nexura-security' ) . '</span>';
                        } elseif ( $cron['status'] === 'nexura' ) {
                            $status_html = '<span style="color: #6366f1; font-weight: 600; display: inline-flex; align-items: center; gap: 6px;"><svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg> ' . __( 'Nexura Task', 'nexura-security' ) . '</span>';
                        } elseif ( $cron['status'] === 'unknown' ) {
                            $status_html = '<span style="color: #f59e0b; font-weight: 600; display: inline-flex; align-items: center; gap: 6px;"><svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg> ' . __( 'Unknown / Third-Party', 'nexura-security' ) . '</span>';
                        } else {
                            $status_html = '<span style="color: #10b981; font-weight: 600; display: inline-flex; align-items: center; gap: 6px;"><svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg> ' . __( 'Safe / Core', 'nexura-security' ) . '</span>';
                        }
                        
                        $args_display = empty( $cron['args'] ) ? __( 'None', 'nexura-security' ) : '<code>' . esc_html( wp_json_encode( $cron['args'] ) ) . '</code>';
                        ?>
                        <tr>
                            <td><strong><?php echo esc_html( $cron['hook'] ); ?></strong></td>
                            <td><?php echo esc_html( wp_date( get_option('date_format') . ' ' . get_option('time_format'), strtotime( get_date_from_gmt( gmdate('Y-m-d H:i:s', $cron['timestamp']) ) ) ) ); ?></td>
                            <td><?php echo esc_html( $cron['schedule'] ); ?></td>
                            <td><?php echo $status_html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></td>
                            <td>
                                <?php if ( ! empty( $cron['reason'] ) ) : ?>
                                    <div style="color: #ef4444; font-size: 12px; margin-bottom: 5px;"><?php echo esc_html( $cron['reason'] ); ?></div>
                                <?php endif; ?>
                                <div style="font-size: 12px; color: var(--nexura-text-muted);">Args: <?php echo $args_display; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></div>
                            </td>
                        </tr>
                        <?php
                    }
                }
                ?>
            </tbody>
        </table>
    </div>

    <?php if ( $total_pages > 1 ) : ?>
        <div class="nexura-pagination" style="margin-top: 20px; display: flex; justify-content: flex-end; align-items: center; gap: 10px;">
            <?php
            echo paginate_links( [ // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
                'base'      => add_query_arg( 'paged', '%#%' ),
                'format'    => '',
                'prev_text' => '&laquo; ' . __( 'Previous', 'nexura-security' ),
                'next_text' => __( 'Next', 'nexura-security' ) . ' &raquo;',
                'total'     => $total_pages,
                'current'   => $current_page,
            ] );
            ?>
        </div>
    <?php endif; ?>
</div>
