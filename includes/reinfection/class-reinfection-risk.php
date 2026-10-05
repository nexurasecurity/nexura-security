<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Reinfection_Risk
 * 
 * Evaluates the total risk level of all detected persistence mechanisms.
 */
class Reinfection_Risk {

    /**
     * Calculate total risk score from evidence.
     * 
     * @param array $evidence Array of detected persistence mechanisms.
     * @return array Array containing total score and risk level (Low, Medium, High, Critical)
     */
    public function calculate_risk( $evidence ) {
        if ( empty( $evidence ) ) {
            return [
                'score' => 0,
                'level' => 'Clean'
            ];
        }

        $total_score = 0;
        foreach ( $evidence as $item ) {
            $score = isset( $item['risk'] ) ? (int) $item['risk'] : 50;
            $total_score += $score;
        }

        // Cap at 100
        $final_score = min( 100, $total_score );

        $level = 'Low';
        if ( $final_score >= 85 ) {
            $level = 'Critical';
        } elseif ( $final_score >= 70 ) {
            $level = 'High';
        } elseif ( $final_score >= 40 ) {
            $level = 'Medium';
        }

        return [
            'score' => $final_score,
            'level' => $level
        ];
    }
}
