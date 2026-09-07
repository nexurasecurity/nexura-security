<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$whitelisted_files = get_option( 'NEXURA_whitelisted_files', [] );
if ( ! is_array( $whitelisted_files ) ) {
    $whitelisted_files = [];
}
?>
<div class="nexura-card nexura-fade-in">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; flex-wrap: wrap; gap: 15px;">
        <div>
            <h2 style="margin: 0;"><span class="nexura-card-icon"><svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg></span> <?php esc_html_e( 'Whitelisted Files', 'nexura-security' ); ?></h2>
            <p style="color: var(--nexura-text-muted); margin: 5px 0 0 0;"><?php esc_html_e( 'Files listed here are explicitly ignored by the malware scanner. Remove them if you want them scanned again.', 'nexura-security' ); ?></p>
        </div>
    </div>
    
    <div style="margin-top: 20px;">
        <?php if ( empty( $whitelisted_files ) ) : ?>
            <div style="padding: 30px; text-align: center; color: var(--nexura-text-muted); border: 1px dashed var(--nexura-border); border-radius: 4px;">
                <span style="font-size: 32px; display: block; margin-bottom: 10px;">🛡️</span>
                No files are currently whitelisted.
            </div>
        <?php else : ?>
            <table class="wp-list-table widefat fixed striped" style="border: 1px solid var(--nexura-border); border-radius: 4px; overflow: hidden;">
                <thead>
                    <tr>
                        <th><?php esc_html_e( 'File Path', 'nexura-security' ); ?></th>
                        <th style="width: 150px; text-align: right;"><?php esc_html_e( 'Action', 'nexura-security' ); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ( $whitelisted_files as $file_path ) : ?>
                        <tr>
                            <td><code><?php echo esc_html( $file_path ); ?></code></td>
                            <td style="text-align: right;">
                                <button type="button" class="button button-small nexura-unwhitelist-file" data-file="<?php echo esc_attr( $file_path ); ?>" style="color: #d63638; border-color: #d63638;">
                                    <?php esc_html_e( 'Remove', 'nexura-security' ); ?>
                                </button>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</div>
