<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Nexura Security - Malware Signature Patterns
 * 
 * This file contains the malware signatures used by the scanner.
 * Strings are split to avoid triggering False Positives in hosting Antivirus/YARA rules.
 */

return [
    'hashes' => [],
    'rules'  => [],
    
    'suspicious_functions' => [
        'ev' . 'al',
        'base64' . '_decode',
        'gzinflate',
        'gzuncompress',
        'gzdecode',
        'str_rot13',
        'create_function',
        'assert',
        'shell_exec',
        'exec',
        'system',
        'passthru',
        'popen',
        'proc_open',
        'pcntl_exec',
        'file_put_contents',
        'curl_exec',
        'file_get_contents',
    ],

    'patterns' => [
        'php_eval_base64' => [
            'pattern'     => '/ev' . 'al\s*\(\s*base64' . '_decode\s*\(/i',
            'risk'        => 'High',
            'description' => 'Common backdoor pattern using eval and base64_decode'
        ],
        'php_wp_vcd' => [
            'pattern'     => '/wp_' . 'vcd/i',
            'risk'        => 'High',
            'description' => 'WP-' . 'VCD malware'
        ],
        'php_phpspider' => [
            'pattern'     => '/php' . 'spider/i',
            'risk'        => 'High',
            'description' => 'PHP ' . 'Spider malware'
        ],
        'php_hex_obfuscation' => [
            'pattern'     => '/(\\\\x[0-9a-fA-F]{2}){5,}/',
            'risk'        => 'Medium',
            'description' => 'Hex encoded obfuscation'
        ],
        'php_b374k' => [
            'pattern'     => '/b37' . '4k/i',
            'risk'        => 'Critical',
            'description' => 'b37' . '4k webshell'
        ],
        'php_r57' => [
            'pattern'     => '/r57' . 'shell/i',
            'risk'        => 'Critical',
            'description' => 'r' . '57 webshell'
        ],
        'php_c99' => [
            'pattern'     => '/c99' . 'shell/i',
            'risk'        => 'Critical',
            'description' => 'c' . '99 webshell'
        ],
        'php_wso' => [
            'pattern'     => '/ws' . 'o\.php/i',
            'risk'        => 'Critical',
            'description' => 'WS' . 'O webshell'
        ],
        'php_filesman' => [
            'pattern'     => '/Files' . 'Man/i',
            'risk'        => 'Critical',
            'description' => 'Files' . 'Man webshell'
        ],
        'php_cookie_post_backdoor' => [
            'pattern'     => '/ev' . 'al\s*\(\s*\$(?:_COOKIE|_PO' . 'ST|_REQUEST)/',
            'risk'        => 'High',
            'description' => 'Direct execution of user input via eval'
        ],
        'php_system_post_backdoor' => [
            'pattern'     => '/(\bsystem|passthru|shell_exec|exec)\s*\(\s*\$(?:_PO' . 'ST|_GET|_COOKIE|_REQUEST)/',
            'risk'        => 'High',
            'description' => 'Command execution backdoor'
        ],
        'php_chr_obfuscation' => [
            'pattern'     => '/(chr\s*\(\s*[0-9]+\s*\*?\s*\$?[^)]*\)\s*\.*){4,}/',
            'risk'        => 'Medium',
            'description' => 'chr() based string obfuscation'
        ],
        'php_defacement' => [
            'pattern'     => '/(hacked\sby|defaced\sby|owned\sby)/i',
            'risk'        => 'High',
            'description' => 'Common defacement signature'
        ],
        'js_td_country_injection' => [
            'pattern'     => '/function\s+td\(\s*country\s*\)/i',
            'risk'        => 'Critical',
            'description' => 'Malicious JS injection: td(country) bot challenge bypass/redirect'
        ]
    ]
];