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

    <?php
    global $wpdb;
    $table_name = $wpdb->prefix . 'NEXURA_audit_logs';

    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    $paged    = isset( $_GET['paged'] ) ? max( 1, intval( $_GET['paged'] ) ) : 1;
    $per_page = 20;
    $offset   = ( $paged - 1 ) * $per_page;

    $actual_table = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
    $table_exists = $actual_table && strcasecmp( $actual_table, $table_name ) === 0;

    $total_items = 0;
    $logs        = [];

    if ( $table_exists ) {
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $total_items = (int) $wpdb->get_var( "SELECT COUNT(id) FROM $table_name" );
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $logs = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM $table_name ORDER BY id DESC LIMIT %d OFFSET %d", $per_page, $offset ) );
    }

    $total_pages = $total_items > 0 ? (int) ceil( $total_items / $per_page ) : 1;
    $from        = $total_items > 0 ? $offset + 1 : 0;
    $to          = min( $offset + $per_page, $total_items );
    ?>

    <?php if ( $total_items > 0 ) : ?>
    <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:12px; flex-wrap:wrap; gap:8px;">
        <span style="font-size:13px; color:var(--nexura-text-muted);">
            <?php
            printf(
                /* translators: 1: from, 2: to, 3: total */
                esc_html__( 'Showing %1$s\xe2\x80\x93%2$s of %3$s entries', 'nexura-security' ),
                '<strong>' . esc_html( number_format_i18n( $from ) ) . '</strong>',
                '<strong>' . esc_html( number_format_i18n( $to ) ) . '</strong>',
                '<strong>' . esc_html( number_format_i18n( $total_items ) ) . '</strong>'
            );
            ?>
        </span>
    </div>
    <?php endif; ?>

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
                <?php if ( ! $table_exists ) : ?>
                <tr>
                    <td colspan="6" style="text-align: center; padding: 30px; color: var(--nexura-text-muted);">
                        <?php esc_html_e( 'Audit logging table is not installed.', 'nexura-security' ); ?>
                    </td>
                </tr>
                <?php elseif ( empty( $logs ) ) : ?>
                <tr>
                    <td colspan="6" style="text-align: center; padding: 30px; color: var(--nexura-text-muted);">
                        <?php esc_html_e( 'No audit logs found.', 'nexura-security' ); ?>
                    </td>
                </tr>
                <?php else : ?>
                    <?php foreach ( $logs as $log ) :
                        $severity_color = '#10b981';
                        if ( $log->severity === 'critical' ) {
                            $severity_color = '#ef4444';
                        } elseif ( $log->severity === 'high' ) {
                            $severity_color = '#f59e0b';
                        } elseif ( $log->severity === 'medium' ) {
                            $severity_color = '#3b82f6';
                        }
                        $badge = sprintf(
                            '<span style="display:inline-block;padding:3px 8px;border-radius:12px;font-size:11px;font-weight:bold;background:%s;color:#fff;">%s</span>',
                            $severity_color,
                            strtoupper( esc_html( $log->severity ) )
                        );
                    ?>
                    <tr>
                        <td><?php echo esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), strtotime( get_date_from_gmt( $log->timestamp ) ) ) ); ?></td>
                        <td><strong><?php echo esc_html( str_replace( '_', ' ', ucfirst( $log->event_type ) ) ); ?></strong></td>
                        <td><?php echo esc_html( $log->username ); ?></td>
                        <td><code><?php echo esc_html( $log->ip_address ); ?></code></td>
                        <td><?php echo $badge; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></td>
                        <td><?php echo esc_html( $log->message ); ?></td>
                    </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>

    <?php
    if ( $total_pages > 1 ) :
        $base_url    = remove_query_arg( 'paged' );
        $window      = 2;
        $pg_start    = max( 1, $paged - $window );
        $pg_end      = min( $total_pages, $paged + $window );

        $s_base    = 'display:inline-flex;align-items:center;justify-content:center;min-width:34px;height:34px;padding:0 8px;border-radius:6px;border:1px solid var(--nexura-border);font-size:13px;text-decoration:none;';
        $s_normal  = $s_base . 'background:var(--nexura-bg-primary);color:var(--nexura-text);';
        $s_active  = $s_base . 'background:var(--nexura-accent,#6366f1);border-color:var(--nexura-accent,#6366f1);color:#fff;font-weight:700;cursor:default;';
        $s_nav     = 'display:inline-flex;align-items:center;gap:4px;padding:6px 14px;height:34px;border-radius:6px;border:1px solid var(--nexura-border);font-size:13px;text-decoration:none;background:var(--nexura-bg-primary);color:var(--nexura-text);';
        $s_nav_dis = 'display:inline-flex;align-items:center;gap:4px;padding:6px 14px;height:34px;border-radius:6px;border:1px solid var(--nexura-border);font-size:13px;background:var(--nexura-bg-card);color:var(--nexura-text-muted);opacity:.45;cursor:not-allowed;';

        $prev_svg = '<svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"></path></svg>';
        $next_svg = '<svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg>';
    ?>
    <div style="margin-top:20px; display:flex; align-items:center; justify-content:center; gap:5px; flex-wrap:wrap;">

        <?php if ( $paged > 1 ) : ?>
            <a href="<?php echo esc_url( add_query_arg( 'paged', $paged - 1, $base_url ) ); ?>" style="<?php echo esc_attr( $s_nav ); ?>">
                <?php echo $prev_svg; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
                <?php esc_html_e( 'Prev', 'nexura-security' ); ?>
            </a>
        <?php else : ?>
            <span style="<?php echo esc_attr( $s_nav_dis ); ?>">
                <?php echo $prev_svg; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
                <?php esc_html_e( 'Prev', 'nexura-security' ); ?>
            </span>
        <?php endif; ?>

        <?php if ( $pg_start > 1 ) : ?>
            <a href="<?php echo esc_url( add_query_arg( 'paged', 1, $base_url ) ); ?>" style="<?php echo esc_attr( $s_normal ); ?>">1</a>
            <?php if ( $pg_start > 2 ) : ?>
                <span style="color:var(--nexura-text-muted);padding:0 4px;line-height:34px;">&#8230;</span>
            <?php endif; ?>
        <?php endif; ?>

        <?php for ( $pg_i = $pg_start; $pg_i <= $pg_end; $pg_i++ ) : ?>
            <?php if ( $pg_i === $paged ) : ?>
                <span style="<?php echo esc_attr( $s_active ); ?>"><?php echo esc_html( $pg_i ); ?></span>
            <?php else : ?>
                <a href="<?php echo esc_url( add_query_arg( 'paged', $pg_i, $base_url ) ); ?>" style="<?php echo esc_attr( $s_normal ); ?>"><?php echo esc_html( $pg_i ); ?></a>
            <?php endif; ?>
        <?php endfor; ?>

        <?php if ( $pg_end < $total_pages ) : ?>
            <?php if ( $pg_end < $total_pages - 1 ) : ?>
                <span style="color:var(--nexura-text-muted);padding:0 4px;line-height:34px;">&#8230;</span>
            <?php endif; ?>
            <a href="<?php echo esc_url( add_query_arg( 'paged', $total_pages, $base_url ) ); ?>" style="<?php echo esc_attr( $s_normal ); ?>"><?php echo esc_html( $total_pages ); ?></a>
        <?php endif; ?>

        <?php if ( $paged < $total_pages ) : ?>
            <a href="<?php echo esc_url( add_query_arg( 'paged', $paged + 1, $base_url ) ); ?>" style="<?php echo esc_attr( $s_nav ); ?>">
                <?php esc_html_e( 'Next', 'nexura-security' ); ?>
                <?php echo $next_svg; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
            </a>
        <?php else : ?>
            <span style="<?php echo esc_attr( $s_nav_dis ); ?>">
                <?php esc_html_e( 'Next', 'nexura-security' ); ?>
                <?php echo $next_svg; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
            </span>
        <?php endif; ?>

    </div>

    <p style="text-align:center; margin-top:10px; font-size:12px; color:var(--nexura-text-muted);">
        <?php
        printf(
            /* translators: 1: current page, 2: total pages */
            esc_html__( 'Page %1$s of %2$s', 'nexura-security' ),
            '<strong>' . esc_html( $paged ) . '</strong>',
            '<strong>' . esc_html( $total_pages ) . '</strong>'
        );
        ?>
    </p>

    <?php endif; ?>

</div>
