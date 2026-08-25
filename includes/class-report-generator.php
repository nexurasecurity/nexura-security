<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Report_Generator
 * 
 * Generates PDF reports using FPDF and sends scheduled scan emails.
 */
class Report_Generator {

    /**
     * Generates a PDF report and emails it or forces download.
     *
     * @param array $response Scan results
     * @param bool  $download Whether to force download instead of emailing
     */
    public static function generate_and_send( $response, $download = false ) {
        // Only require FPDF when we actually need to generate a PDF
        if ( ! class_exists( 'FPDF' ) ) {
            $fpdf_path = NEXURA_PLUGIN_DIR . 'vendor/fpdf/fpdf.php';
            if ( file_exists( $fpdf_path ) ) {
                require_once $fpdf_path;
            } else {
                // Fallback to plain text if FPDF is somehow missing
                self::send_plain_text_email( $response );
                return;
            }
        }

        $issues    = isset( $response['issues'] ) ? intval( $response['issues'] ) : 0;
        $processed = isset( $response['processed'] ) ? intval( $response['processed'] ) : 0;
        $is_pro    = function_exists( 'nexura_is_pro' ) && nexura_is_pro();

        // 1. Generate PDF
        $pdf = new \FPDF();
        $pdf->AddPage();
        
        // Header
        $pdf->SetFont( 'Arial', 'B', 16 );
        $pdf->SetTextColor( 11, 19, 43 ); // Dark Blue
        $pdf->Cell( 0, 10, 'Nexura Security Scan Report', 0, 1, 'C' );
        
        $pdf->SetFont( 'Arial', 'I', 10 );
        $pdf->SetTextColor( 100, 100, 100 );
        $pdf->Cell( 0, 10, 'Generated on ' . gmdate( 'Y-m-d H:i:s' ) . ' (UTC)', 0, 1, 'C' );
        $pdf->Ln( 5 );

        // Site Info
        $pdf->SetFont( 'Arial', 'B', 12 );
        $pdf->SetTextColor( 0, 0, 0 );
        $pdf->Cell( 0, 8, 'Website: ' . get_bloginfo( 'name' ) . ' (' . site_url() . ')', 0, 1 );
        $pdf->Cell( 0, 8, 'Total Files Scanned: ' . number_format( $processed ), 0, 1 );
        
        if ( $issues > 0 ) {
            $pdf->SetTextColor( 230, 57, 70 ); // Red
            $pdf->Cell( 0, 8, 'Malware Threats Detected: ' . $issues, 0, 1 );
        } else {
            $pdf->SetTextColor( 34, 139, 34 ); // Green
            $pdf->Cell( 0, 8, 'Malware Threats Detected: 0 (Site is Clean)', 0, 1 );
        }
        $pdf->Ln( 10 );

        // Details Section
        $pdf->SetTextColor( 0, 0, 0 );
        if ( $issues > 0 ) {
            if ( $is_pro ) {
                $pdf->SetFont( 'Arial', 'B', 12 );
                $pdf->Cell( 0, 10, 'Detailed Threat List:', 0, 1 );
                
                $pdf->SetFont( 'Arial', '', 10 );
                // Fetch issues from database
                global $wpdb;
                $table_name = $wpdb->prefix . 'NEXURA_scan_results';
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
                $findings = $wpdb->get_results( "SELECT file_path, risk_score FROM {$table_name} ORDER BY id DESC LIMIT 100" );
                
                if ( $findings ) {
                    foreach ( $findings as $finding ) {
                        // MultiCell for long file paths
                        $pdf->SetFont( 'Arial', 'B', 10 );
                        $pdf->Write( 6, 'Risk: ' . esc_html( $finding->risk_score ) . ' | ' );
                        $pdf->SetFont( 'Arial', '', 10 );
                        $pdf->MultiCell( 0, 6, esc_html( $finding->file_path ) );
                        $pdf->Ln( 2 );
                    }
                    if ( count( $findings ) == 100 ) {
                        $pdf->Cell( 0, 6, '... showing the first 100 threats.', 0, 1 );
                    }
                } else {
                    $pdf->Cell( 0, 6, 'No specific file paths recorded in the database.', 0, 1 );
                }
            } else {
                // Free Version - Upsell
                $pdf->SetFont( 'Arial', 'I', 11 );
                $pdf->SetTextColor( 85, 85, 85 );
                $pdf->MultiCell( 0, 8, 'Detailed file paths are omitted in the Free version. Upgrade to Nexura Security Pro to see exactly which files are infected, and use our one-click malware removal tool to secure your site.' );
            }
        }

        if ( $download ) {
            $pdf->Output( 'D', 'nexura-security-report-' . current_time( 'Y-m-d' ) . '.pdf' );
            return;
        }

        // Output PDF to a temporary file
        $upload_dir = wp_upload_dir();
        $pdf_dir = $upload_dir['basedir'] . '/nexura-reports';
        if ( ! is_dir( $pdf_dir ) ) {
            wp_mkdir_p( $pdf_dir );
        }
        
        $filename = 'scan-report-' . current_time( 'Y-m-d' ) . '.pdf';
        $filepath = $pdf_dir . '/' . $filename;
        
        // Save PDF to file
        $pdf->Output( 'F', $filepath );

        // 2. Send Email with Attachment
        $to = get_option( 'admin_email' );
        $subject = '[' . get_bloginfo( 'name' ) . '] Nexura Security - Scheduled Scan Report';
        
        $message = "Hello,\n\n";
        $message .= "Nexura Security has completed a background malware scan on your website.\n\n";
        $message .= "Scan Summary:\n";
        $message .= "- Files Processed: " . number_format( $processed ) . "\n";
        $message .= "- Issues Detected: " . $issues . "\n\n";
        
        if ( $issues > 0 ) {
            $message .= "WARNING: Threats were found on your site. Please review the attached PDF report and take action immediately.\n\n";
        } else {
            $message .= "Great news! Your website appears to be clean.\n\n";
        }

        if ( ! $is_pro ) {
            $message .= "---\n";
            $message .= "🔒 UPGRADE TO NEXURA SECURITY PRO 🔒\n";
            $message .= "Get detailed PDF reports, active malware blocking, and automated cleanup.\n";
            $message .= "Upgrade today to keep your site fully secured!\n";
        }
        
        wp_mail( $to, $subject, $message, '', [ $filepath ] );

        // 3. Clean up the temporary PDF file
        if ( file_exists( $filepath ) ) {
            wp_delete_file( $filepath );
        }
    }

    /**
     * Fallback for sending plain text email if PDF generation fails.
     */
    private static function send_plain_text_email( $response ) {
        $issues = isset( $response['issues'] ) ? intval( $response['issues'] ) : 0;
        $processed = isset( $response['processed'] ) ? intval( $response['processed'] ) : 0;
        
        $to = get_option( 'admin_email' );
        $subject = '[' . get_bloginfo('name') . '] Nexura Security - Scheduled Scan Report';
        
        $message = "Hello,\n\n";
        $message .= "Nexura Security has completed a malware scan on your website.\n\n";
        $message .= "Scan Results:\n";
        $message .= "- Files Processed: " . number_format($processed) . "\n";
        $message .= "- Issues Detected: " . $issues . "\n\n";
        
        if ( $issues > 0 ) {
            $message .= "Action Required: Please log in to your dashboard to resolve these threats.\n\n";
        } else {
            $message .= "Your website appears to be clean.\n\n";
        }
        
        wp_mail( $to, $subject, $message );
    }
}
