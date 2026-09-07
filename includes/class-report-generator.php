<?php

namespace Nexura_Security;

if ( !defined( 'ABSPATH' ) ) {
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
        if ( !class_exists( 'FPDF' ) ) {
            $fpdf_path = NEXURA_PLUGIN_DIR . 'vendor/fpdf/fpdf.php';
            if ( file_exists( $fpdf_path ) ) {
                require_once $fpdf_path;
            } else {
                // Fallback to plain text if FPDF is somehow missing
                self::send_plain_text_email( $response );
                return;
            }
        }
        $issues = ( isset( $response['issues'] ) ? intval( $response['issues'] ) : 0 );
        $processed = ( isset( $response['processed'] ) ? intval( $response['processed'] ) : 0 );
        // 1. Generate PDF
        $pdf = new class extends \FPDF {
            private $angle = 0;

            public function Rotate( $angle, $x = -1, $y = -1 ) {
                if ( $x == -1 ) {
                    $x = $this->x;
                }
                if ( $y == -1 ) {
                    $y = $this->y;
                }
                if ( $this->angle != 0 ) {
                    $this->_out( 'Q' );
                }
                $this->angle = $angle;
                if ( $angle != 0 ) {
                    $angle *= M_PI / 180;
                    $c = cos( $angle );
                    $s = sin( $angle );
                    $cx = $x * $this->k;
                    $cy = ($this->h - $y) * $this->k;
                    $this->_out( sprintf(
                        'q %.5F %.5F %.5F %.5F %.2F %.2F cm 1 0 0 1 %.2F %.2F cm',
                        $c,
                        $s,
                        -$s,
                        $c,
                        $cx,
                        $cy,
                        -$cx,
                        -$cy
                    ) );
                }
            }

            public function _endpage() {
                if ( $this->angle != 0 ) {
                    $this->angle = 0;
                    $this->_out( 'Q' );
                }
                parent::_endpage();
            }

            public function Header() {
                // Save current Y
                $current_y = $this->GetY();
                // Background Watermark
                $this->SetFont( 'Arial', 'B', 50 );
                $this->SetTextColor( 242, 242, 242 );
                // Very light gray watermark
                $this->Rotate( 45, 105, 148 );
                $w = $this->GetStringWidth( 'NEXURA SECURITY' );
                $this->SetXY( 105 - $w / 2, 148 );
                $this->Cell(
                    $w,
                    10,
                    'NEXURA SECURITY',
                    0,
                    0,
                    'C'
                );
                $this->Rotate( 0 );
                // Restore Y for actual content rendering
                $this->SetY( $current_y );
            }

            public function Footer() {
                $this->SetY( -15 );
                $this->SetFont( 'Arial', 'I', 9 );
                $this->SetTextColor( 120, 120, 120 );
                $this->Cell(
                    0,
                    10,
                    'https://nexurasecurity.com/   |   Email Support: support@nexurasecurity.com',
                    0,
                    0,
                    'C'
                );
            }

        }
;
        $pdf->AddPage();
        // Header Bar (Dark Gray)
        $pdf->SetFillColor( 74, 74, 74 );
        // Dark Gray
        $pdf->Rect(
            0,
            0,
            210,
            12,
            'F'
        );
        $pdf->SetFont( 'Arial', '', 10 );
        $pdf->SetTextColor( 255, 255, 255 );
        $pdf->SetXY( 10, 2 );
        $pdf->Cell(
            100,
            8,
            'Nexura Security Vulnerability Report',
            0,
            0,
            'L'
        );
        $pdf->Cell(
            90,
            8,
            get_bloginfo( 'name' ),
            0,
            1,
            'R'
        );
        $pdf->Ln( 10 );
        // Title
        $pdf->SetTextColor( 0, 0, 0 );
        $pdf->SetFont( 'Arial', 'B', 22 );
        $pdf->Cell(
            0,
            12,
            'Summary',
            0,
            1
        );
        // Meta
        $pdf->SetFont( 'Arial', '', 10 );
        $pdf->SetTextColor( 100, 100, 100 );
        $pdf->Cell(
            35,
            6,
            'Report Generated:',
            0,
            0
        );
        $pdf->SetTextColor( 0, 0, 0 );
        $pdf->SetFont( 'Arial', 'B', 10 );
        $pdf->Cell(
            0,
            6,
            gmdate( 'D M d H:i:s Y' ) . ' UTC',
            0,
            1
        );
        $pdf->SetFont( 'Arial', '', 10 );
        $pdf->SetTextColor( 100, 100, 100 );
        $pdf->Cell(
            35,
            6,
            'Target Website:',
            0,
            0
        );
        $pdf->SetTextColor( 0, 0, 0 );
        $pdf->SetFont( 'Arial', 'B', 10 );
        $pdf->Cell(
            0,
            6,
            site_url(),
            0,
            1
        );
        $pdf->Ln( 8 );
        // Colored Metric Blocks
        $y_blocks = $pdf->GetY();
        // HIGH Box (Red)
        $pdf->SetFillColor( 217, 83, 79 );
        $pdf->Rect(
            10,
            $y_blocks,
            60,
            25,
            'F'
        );
        $pdf->SetFillColor( 193, 46, 42 );
        $pdf->Rect(
            10,
            $y_blocks + 18,
            60,
            7,
            'F'
        );
        $pdf->SetTextColor( 255, 255, 255 );
        $pdf->SetFont( 'Arial', 'B', 24 );
        $pdf->SetXY( 10, $y_blocks + 3 );
        $pdf->Cell(
            60,
            12,
            $issues,
            0,
            0,
            'C'
        );
        $pdf->SetFont( 'Arial', '', 9 );
        $pdf->SetXY( 10, $y_blocks + 18 );
        $pdf->Cell(
            60,
            7,
            'HIGH',
            0,
            0,
            'C'
        );
        // MEDIUM Box (Orange)
        $pdf->SetFillColor( 240, 173, 78 );
        $pdf->Rect(
            75,
            $y_blocks,
            60,
            25,
            'F'
        );
        $pdf->SetFillColor( 219, 139, 11 );
        $pdf->Rect(
            75,
            $y_blocks + 18,
            60,
            7,
            'F'
        );
        $pdf->SetFont( 'Arial', 'B', 24 );
        $pdf->SetXY( 75, $y_blocks + 3 );
        $pdf->Cell(
            60,
            12,
            '0',
            0,
            0,
            'C'
        );
        $pdf->SetFont( 'Arial', '', 9 );
        $pdf->SetXY( 75, $y_blocks + 18 );
        $pdf->Cell(
            60,
            7,
            'MEDIUM',
            0,
            0,
            'C'
        );
        // SCANNED Box (Blue)
        $pdf->SetFillColor( 2, 117, 216 );
        $pdf->Rect(
            140,
            $y_blocks,
            60,
            25,
            'F'
        );
        $pdf->SetFillColor( 2, 90, 165 );
        $pdf->Rect(
            140,
            $y_blocks + 18,
            60,
            7,
            'F'
        );
        $pdf->SetFont( 'Arial', 'B', 24 );
        $pdf->SetXY( 140, $y_blocks + 3 );
        $pdf->Cell(
            60,
            12,
            number_format( $processed ),
            0,
            0,
            'C'
        );
        $pdf->SetFont( 'Arial', '', 9 );
        $pdf->SetXY( 140, $y_blocks + 18 );
        $pdf->Cell(
            60,
            7,
            'SCANNED',
            0,
            0,
            'C'
        );
        $pdf->SetXY( 10, $y_blocks + 32 );
        // Executive Summary
        $pdf->SetTextColor( 60, 60, 60 );
        $pdf->SetFont( 'Arial', '', 10 );
        if ( $issues > 0 ) {
            $pdf->MultiCell( 0, 5, "Executive Summary: The vulnerability scan has detected {$issues} HIGH severity threat(s). These are actively infected files that pose a severe risk to your website's security, data integrity, and reputation. Immediate remediation is strongly advised to prevent further exploitation." );
        } else {
            $pdf->MultiCell( 0, 5, "Executive Summary: The vulnerability scan found no high-severity threats. Your website appears to be clean and secure across the " . number_format( $processed ) . " files scanned. We recommend maintaining regular automated scans to ensure continuous protection." );
        }
        $pdf->Ln( 8 );
        // Host Summary
        $pdf->SetTextColor( 0, 0, 0 );
        $pdf->SetFont( 'Arial', 'B', 14 );
        $pdf->Cell(
            0,
            10,
            'Host Summary',
            0,
            1
        );
        $pdf->SetFillColor( 230, 230, 230 );
        $pdf->SetFont( 'Arial', 'B', 9 );
        $pdf->Cell(
            80,
            8,
            'Host',
            1,
            0,
            'L',
            true
        );
        $pdf->Cell(
            40,
            8,
            'Scanned Files',
            1,
            0,
            'C',
            true
        );
        $pdf->Cell(
            35,
            8,
            'High',
            1,
            0,
            'C',
            true
        );
        $pdf->Cell(
            35,
            8,
            'Medium',
            1,
            1,
            'C',
            true
        );
        $pdf->SetFont( 'Arial', '', 9 );
        $pdf->Cell(
            80,
            8,
            get_bloginfo( 'url' ),
            1,
            0,
            'L'
        );
        $pdf->Cell(
            40,
            8,
            number_format( $processed ),
            1,
            0,
            'C'
        );
        $pdf->Cell(
            35,
            8,
            $issues,
            1,
            0,
            'C'
        );
        $pdf->Cell(
            35,
            8,
            '0',
            1,
            1,
            'C'
        );
        $pdf->Ln( 8 );
        // Vulnerability Summary
        $pdf->SetFont( 'Arial', 'B', 14 );
        $pdf->Cell(
            0,
            10,
            'Vulnerability Summary',
            0,
            1
        );
        $pdf->SetFillColor( 230, 230, 230 );
        $pdf->SetFont( 'Arial', 'B', 9 );
        $pdf->Cell(
            25,
            8,
            'Severity',
            1,
            0,
            'C',
            true
        );
        $pdf->Cell(
            115,
            8,
            'File Path / Description',
            1,
            0,
            'L',
            true
        );
        $pdf->Cell(
            50,
            8,
            'Action Required',
            1,
            1,
            'L',
            true
        );
        $pdf->SetFont( 'Arial', '', 9 );
        if ( $issues > 0 ) {
            $show_upsell = true;
            if ( function_exists( 'nsp_fs' ) && nsp_fs()->can_use_premium_code__premium_only() ) {
                $show_upsell = false;
                global $wpdb;
                $table_name = $wpdb->prefix . 'NEXURA_scan_results';
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                $findings = $wpdb->get_results( "SELECT file_path, risk_score FROM {$table_name} WHERE status = 'infected' LIMIT 100" );
                if ( $findings ) {
                    foreach ( $findings as $finding ) {
                        $pdf->SetFillColor( 217, 83, 79 );
                        // Red
                        $pdf->SetTextColor( 255, 255, 255 );
                        $pdf->Cell(
                            25,
                            8,
                            'High',
                            1,
                            0,
                            'C',
                            true
                        );
                        $pdf->SetTextColor( 0, 0, 0 );
                        $file_truncated = ( strlen( $finding->file_path ) > 60 ? substr( $finding->file_path, 0, 57 ) . '...' : $finding->file_path );
                        $pdf->Cell(
                            115,
                            8,
                            $file_truncated,
                            1,
                            0,
                            'L'
                        );
                        $pdf->SetTextColor( 217, 83, 79 );
                        $pdf->SetFont( 'Arial', 'B', 8 );
                        $pdf->Cell(
                            50,
                            8,
                            'Remove or Quarantine',
                            1,
                            1,
                            'L'
                        );
                        $pdf->SetFont( 'Arial', '', 9 );
                    }
                } else {
                    $pdf->Cell(
                        190,
                        8,
                        'No specific file paths found in database.',
                        1,
                        1,
                        'C'
                    );
                }
            }
            if ( $show_upsell ) {
                $pdf->SetTextColor( 85, 85, 85 );
                $pdf->Cell(
                    25,
                    8,
                    'High',
                    1,
                    0,
                    'C'
                );
                $pdf->Cell(
                    115,
                    8,
                    '[Path omitted in Free Version]',
                    1,
                    0,
                    'C'
                );
                $pdf->Cell(
                    50,
                    8,
                    'Upgrade to Pro',
                    1,
                    1,
                    'C'
                );
                $pdf->Ln( 5 );
                $pdf->SetFont( 'Arial', 'I', 9 );
                $pdf->MultiCell( 0, 5, "Remediation Advice:\nDetailed file paths and 1-click malware removal tools are available in Nexura Security Pro. Please upgrade to Pro to securely clean these infections, or manually inspect your files for malicious code changes." );
            }
        } else {
            $pdf->Cell(
                190,
                8,
                'No vulnerabilities found. System is secure.',
                1,
                1,
                'C'
            );
        }
        if ( $download ) {
            $pdf->Output( 'D', 'nexura-security-report-' . current_time( 'Y-m-d' ) . '.pdf' );
            return;
        }
        // Output PDF to a temporary file
        $upload_dir = wp_upload_dir();
        $pdf_dir = $upload_dir['basedir'] . '/nexura-reports';
        if ( !is_dir( $pdf_dir ) ) {
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
        $show_email_upsell = true;
        if ( function_exists( 'nsp_fs' ) ) {
        }
        if ( $show_email_upsell ) {
            $message .= "---\n";
            $message .= "🔒 UPGRADE TO NEXURA SECURITY PRO 🔒\n";
            $message .= "Get detailed PDF reports, active malware blocking, and automated cleanup.\n";
            $message .= "Upgrade today to keep your site fully secured!\n";
        }
        wp_mail(
            $to,
            $subject,
            $message,
            '',
            [$filepath]
        );
        // 3. Clean up the temporary PDF file
        if ( file_exists( $filepath ) ) {
            wp_delete_file( $filepath );
        }
    }

    /**
     * Fallback for sending plain text email if PDF generation fails.
     */
    private static function send_plain_text_email( $response ) {
        $issues = ( isset( $response['issues'] ) ? intval( $response['issues'] ) : 0 );
        $processed = ( isset( $response['processed'] ) ? intval( $response['processed'] ) : 0 );
        $to = get_option( 'admin_email' );
        $subject = '[' . get_bloginfo( 'name' ) . '] Nexura Security - Scheduled Scan Report';
        $message = "Hello,\n\n";
        $message .= "Nexura Security has completed a malware scan on your website.\n\n";
        $message .= "Scan Results:\n";
        $message .= "- Files Processed: " . number_format( $processed ) . "\n";
        $message .= "- Issues Detected: " . $issues . "\n\n";
        if ( $issues > 0 ) {
            $message .= "Action Required: Please log in to your dashboard to resolve these threats.\n\n";
        } else {
            $message .= "Your website appears to be clean.\n\n";
        }
        wp_mail( $to, $subject, $message );
    }

}
