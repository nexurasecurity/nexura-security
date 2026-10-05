<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class File_Writer_Analyzer
 * 
 * Uses PHP Tokenizer to accurately find file-writing capabilities
 * and remote downloader mechanisms in PHP files.
 */
class File_Writer_Analyzer {

    /**
     * Common file writing functions in PHP.
     */
    private $writer_functions = [
        'file_put_contents',
        'fwrite',
        'fputs',
        'copy',
        'rename',
        'move_uploaded_file'
    ];

    /**
     * Common remote fetching functions.
     */
    private $remote_functions = [
        'file_get_contents',
        'curl_exec',
        'wp_remote_get',
        'wp_remote_request',
        'fsockopen'
    ];

    /**
     * Analyze a file using PHP tokens.
     * 
     * @param string $file_path Path to the PHP file.
     * @return array Analysis results [ 'is_writer' => bool, 'is_downloader' => bool, 'functions' => array ]
     */
    public function analyze_file( $file_path ) {
        $result = [
            'is_writer'     => false,
            'is_downloader' => false,
            'functions'     => []
        ];

        if ( ! file_exists( $file_path ) || filesize( $file_path ) > 1048576 ) {
            // Skip large files (> 1MB) for performance and memory protection
            return $result;
        }

        $code = file_get_contents( $file_path );
        $tokens = token_get_all( $code );

        foreach ( $tokens as $token ) {
            if ( is_array( $token ) ) {
                if ( $token[0] === T_STRING ) {
                    $func_name = strtolower( $token[1] );
                    
                    if ( in_array( $func_name, $this->writer_functions, true ) ) {
                        $result['is_writer'] = true;
                        if ( ! in_array( $func_name, $result['functions'], true ) ) {
                            $result['functions'][] = $func_name;
                        }
                    }

                    if ( in_array( $func_name, $this->remote_functions, true ) ) {
                        $result['is_downloader'] = true;
                        if ( ! in_array( $func_name, $result['functions'], true ) ) {
                            $result['functions'][] = $func_name;
                        }
                    }
                }
            }
        }

        return $result;
    }

    /**
     * Scan a list of files to find potential File Writers.
     * 
     * @param array $file_paths Array of absolute paths.
     * @return array
     */
    public function find_writers( $file_paths ) {
        $writers = [];
        foreach ( $file_paths as $path ) {
            $analysis = $this->analyze_file( $path );
            if ( $analysis['is_writer'] ) {
                $writers[] = [
                    'path'      => $path,
                    'functions' => $analysis['functions']
                ];
            }
        }
        return $writers;
    }
}
