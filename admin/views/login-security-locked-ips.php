<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

global $wpdb;

// Handle Unblock Action
if ( isset( $_POST['unblock_ip'] ) && isset( $_POST['_wpnonce'] ) ) {
    if ( wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'nexura_unblock_ip' ) ) {
        $ip_to_unblock = sanitize_text_field( wp_unslash( $_POST['unblock_ip'] ) );
        delete_transient( 'NEXURA_login_attempts_' . $ip_to_unblock );
        delete_transient( 'NEXURA_lockout_expiry_' . $ip_to_unblock );
        delete_transient( 'NEXURA_lockout_data_' . $ip_to_unblock );
        
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'IP address successfully unblocked.', 'nexura-security' ) . '</p></div>';
    }
}

// Fetch all active lockouts from wp_options
// We query for the expiry transient keys since they represent active lockouts
$results = $wpdb->get_results(
    "SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE '_transient_NEXURA_lockout_expiry_%'"
);

$locked_ips = [];

if ( $results ) {
    $now = time();
    foreach ( $results as $row ) {
        $expiry_time = (int) $row->option_value;
        if ( $expiry_time > $now ) {
            // Extract IP from option_name (e.g. _transient_NEXURA_lockout_expiry_127.0.0.1)
            $ip = str_replace( '_transient_NEXURA_lockout_expiry_', '', $row->option_name );
            
            // Get extra data
            $extra_data = get_transient( 'NEXURA_lockout_data_' . $ip );
            $username = isset( $extra_data['username'] ) ? $extra_data['username'] : __( 'Unknown', 'nexura-security' );
            $strike   = isset( $extra_data['strike'] ) ? $extra_data['strike'] : 1;
            
            $locked_ips[] = [
                'ip'       => $ip,
                'username' => $username,
                'strike'   => $strike,
                'expiry'   => $expiry_time
            ];
        }
    }
}
?>

<div class="nexura-settings-section">
    <h3><?php esc_html_e( 'Currently Locked IP Addresses', 'nexura-security' ); ?></h3>
    <p><?php esc_html_e( 'These IP addresses have been temporarily blocked from logging in due to repeated failed attempts.', 'nexura-security' ); ?></p>

    <table class="wp-list-table widefat fixed striped" style="margin-top: 15px;">
        <thead>
            <tr>
                <th><?php esc_html_e( 'IP Address', 'nexura-security' ); ?></th>
                <th><?php esc_html_e( 'Targeted Username', 'nexura-security' ); ?></th>
                <th><?php esc_html_e( 'Strike Level', 'nexura-security' ); ?></th>
                <th><?php esc_html_e( 'Time Remaining', 'nexura-security' ); ?></th>
                <th><?php esc_html_e( 'Actions', 'nexura-security' ); ?></th>
            </tr>
        </thead>
        <tbody>
            <?php if ( empty( $locked_ips ) ) : ?>
                <tr>
                    <td colspan="5"><?php esc_html_e( 'No IP addresses are currently locked out.', 'nexura-security' ); ?></td>
                </tr>
            <?php else : ?>
                <?php foreach ( $locked_ips as $lockout ) : 
                    $remaining = $lockout['expiry'] - time();
                    $hours = floor( $remaining / 3600 );
                    $minutes = floor( ( $remaining % 3600 ) / 60 );
                    
                    if ( $hours > 0 ) {
                        $time_string = sprintf( __( '%dh %dm', 'nexura-security' ), $hours, $minutes );
                    } else {
                        $time_string = sprintf( __( '%dm', 'nexura-security' ), $minutes );
                    }
                ?>
                    <tr>
                        <td><strong><?php echo esc_html( $lockout['ip'] ); ?></strong></td>
                        <td><?php echo esc_html( $lockout['username'] ); ?></td>
                        <td><?php echo esc_html( $lockout['strike'] ); ?></td>
                        <td><?php echo esc_html( $time_string ); ?></td>
                        <td>
                            <form method="post" style="display:inline-block;">
                                <?php wp_nonce_field( 'nexura_unblock_ip' ); ?>
                                <input type="hidden" name="unblock_ip" value="<?php echo esc_attr( $lockout['ip'] ); ?>">
                                <button type="submit" class="button button-small button-primary" onclick="return confirm('<?php esc_attr_e( 'Are you sure you want to unblock this IP address?', 'nexura-security' ); ?>');">
                                    <?php esc_html_e( 'Unblock IP', 'nexura-security' ); ?>
                                </button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            <?php endif; ?>
        </tbody>
    </table>
</div>
