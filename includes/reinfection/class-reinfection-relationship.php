<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Reinfection_Relationship
 * 
 * Maps the relationship between a generated malware file and its parent/creator mechanism.
 */
class Reinfection_Relationship {

    /**
     * Build the relationship graph based on evidence.
     * 
     * @param string $target_file The malicious file being investigated.
     * @param array  $evidence     Array of evidence gathered by detectors.
     * @return array The relationship mapping.
     */
    public function build_relationship( $target_file, $evidence ) {
        $graph = [
            'target' => $target_file,
            'nodes'  => [],
            'edges'  => []
        ];

        // Ensure target is a node
        $graph['nodes'][] = [
            'id'    => 'target',
            'label' => basename( $target_file ),
            'group' => 'malware'
        ];

        // Process evidence to build edges
        $counter = 1;
        foreach ( $evidence as $item ) {
            $node_id = 'node_' . $counter;
            $graph['nodes'][] = [
                'id'    => $node_id,
                'label' => isset( $item['path'] ) ? basename( $item['path'] ) : $item['type'],
                'group' => $item['type'],
                'risk'  => isset( $item['risk'] ) ? $item['risk'] : 0,
                'desc'  => isset( $item['evidence'] ) ? $item['evidence'] : ''
            ];

            // In a real scenario, this would have complex logic to determine
            // if this specific node actually wrote the target. For now, we link them.
            $graph['edges'][] = [
                'from'  => $node_id,
                'to'    => 'target',
                'label' => 'Created / Triggered'
            ];

            $counter++;
        }

        return $graph;
    }
}
