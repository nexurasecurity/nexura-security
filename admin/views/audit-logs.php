<?php
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>

<div class="nexura-card nexura-fade-in">
    <h2><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg></span> <?php esc_html_e( 'Admin & User Audit Logs', 'nexura-security' ); ?></h2>
    
    <p class="description" style="margin-bottom: 20px;">
        <?php esc_html_e( 'Tracks critical user events such as new administrator creations, privilege escalations, and suspicious logins.', 'nexura-security' ); ?>
    </p>

    <div style="background: var(--nexura-bg-card); border-radius: 8px; border: 1px solid var(--nexura-border); overflow: hidden;">
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th scope="col" style="width: 15%;"><?php esc_html_e( 'Date & Time', 'nexura-security' ); ?></th>
                    <th scope="col" style="width: 15%;"><?php esc_html_e( 'Event Type', 'nexura-security' ); ?></th>
                    <th scope="col" style="width: 15%;"><?php esc_html_e( 'User', 'nexura-security' ); ?></th>
                    <th scope="col" style="width: 10%;"><?php esc_html_e( 'IP Address', 'nexura-security' ); ?></th>
                    <th scope="col" style="width: 10%;"><?php esc_html_e( 'Severity', 'nexura-security' ); ?></th>
                    <th scope="col"><?php esc_html_e( 'Message', 'nexura-security' ); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php
                global $wpdb;
                $table_name = $wpdb->prefix . 'NEXURA_audit_logs';
                
                // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                $paged = isset( $_GET['paged'] ) ? max( 1, intval( $_GET['paged'] ) ) : 1;
                $per_page = 20;
                $offset = ( $paged - 1 ) * $per_page;

                // Check if table exists
                $actual_table = $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table_name ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                if ( $actual_table && strcasecmp( $actual_table, $table_name ) === 0 ) {
                    
                    // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                    $total_items = $wpdb->get_var( "SELECT COUNT(id) FROM $table_name" );
                    // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                    $logs = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM $table_name ORDER BY id DESC LIMIT %d OFFSET %d", $per_page, $offset ) );

                    if ( $logs ) {
                        foreach ( $logs as $log ) {
                            $severity_color = '#10b981'; // Green
                            if ( $log->severity === 'critical' ) {
                                $severity_color = '#ef4444'; // Red
                            } elseif ( $log->severity === 'high' ) {
                                $severity_color = '#f59e0b'; // Orange
                            } elseif ( $log->severity === 'medium' ) {
                                $severity_color = '#3b82f6'; // Blue
                            }

                            $badge = sprintf( '<span style="display:inline-block; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; background: %s; color: #fff;">%s</span>', $severity_color, strtoupper( esc_html( $log->severity ) ) );
                            ?>
                            <tr>
                                <td><?php echo esc_html( wp_date( get_option('date_format') . ' ' . get_option('time_format'), strtotime( get_date_from_gmt( $log->timestamp ) ) ) ); ?></td>
                                <td><strong><?php echo esc_html( str_replace( '_', ' ', ucfirst( $log->event_type ) ) ); ?></strong></td>
                                <td><?php echo esc_html( $log->username ); ?></td>
                                <td><code><?php echo esc_html( $log->ip_address ); ?></code></td>
                                <td><?php echo $badge; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></td>
                                <td><?php echo esc_html( $log->message ); ?></td>
                            </tr>
                            <?php
                        }
                    } else {
                        ?>
                        <tr>
                            <td colspan="6" style="text-align: center; padding: 20px; color: var(--nexura-text-muted);">
                                <?php esc_html_e( 'No audit logs found.', 'nexura-security' ); ?>
                            </td>
                        </tr>
                        <?php
                    }
                } else {
                    ?>
                    <tr>
                        <td colspan="6" style="text-align: center; padding: 20px; color: var(--nexura-text-muted);">
                            <?php esc_html_e( 'Audit logging table is not installed.', 'nexura-security' ); ?>
                        </td>
                    </tr>
                    <?php
                }
                ?>
            </tbody>
        </table>
    </div>

    <?php
    if ( isset( $total_items ) && $total_items > $per_page ) {
        $total_pages = ceil( $total_items / $per_page );
        $page_links = paginate_links( [
            'base' => add_query_arg( 'paged', '%#%' ),
            'format' => '',
            'prev_text' => __( '&laquo;', 'nexura-security' ),
            'next_text' => __( '&raquo;', 'nexura-security' ),
            'total' => $total_pages,
            'current' => $paged,
            'type' => 'array'
        ] );

        if ( $page_links ) {
            echo '<div style="margin-top: 15px; display: flex; gap: 5px;">';
            foreach ( $page_links as $link ) {
                echo '<span class="nexura-pagination-link" style="display:inline-block; background: var(--nexura-bg-primary); padding: 5px 10px; border-radius: 4px; border: 1px solid var(--nexura-border);">' . $link . '</span>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            }
            echo '</div>';
        }
    }
    ?>
</div>
