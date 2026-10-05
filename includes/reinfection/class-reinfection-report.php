<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Reinfection_Report
 * 
 * Compiles all data from detectors, analyzers, and graph builder
 * into a structured report for the UI.
 */
class Reinfection_Report {

    /**
     * Generate the final investigation report.
     * 
     * @param string $target_file The investigated file.
     * @param array  $evidence     Array of persistence mechanisms detected.
     * @param array  $graph        The relationship graph data.
     * @param array  $risk         The calculated risk.
     * @return array The complete report.
     */
    public function generate_report( $target_file, $evidence, $graph, $risk ) {
        return [
            'timestamp'   => current_time( 'mysql' ),
            'target_file' => $target_file,
            'risk_level'  => $risk['level'],
            'risk_score'  => $risk['score'],
            'evidence'    => $evidence,
            'graph_data'  => $graph,
            'summary'     => $this->generate_summary( $evidence, $risk )
        ];
    }

    /**
     * Generate a human-readable summary of the findings.
     * 
     * @param array $evidence
     * @param array $risk
     * @return string
     */
    private function generate_summary( $evidence, $risk ) {
        if ( empty( $evidence ) ) {
            return __( 'No persistence mechanisms found. The system appears clean.', 'nexura-security' );
        }

        $count = count( $evidence );
        return sprintf(
            /* translators: 1: Risk level, 2: Number of mechanisms */
            __( 'Investigation complete. Overall risk is %1$s. We found %2$d potential persistence mechanisms that might be recreating the malware.', 'nexura-security' ),
            $risk['level'],
            $count
        );
    }
}
