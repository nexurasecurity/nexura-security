<?php
/**
 * Nexura Security - Backdoor Signature Database
 *
 * @version    1.2.0
 * @updated    2026-09-02
 *
 * Format per entry:
 *   'key' => [
 *       'pattern'     => '/regex/flags',   // PCRE regex
 *       'description' => 'Human text',
 *       'risk'        => 'Critical|High|Medium|Low',
 *       'confidence'  => 0-100,
 *   ]
 *
 * NOTE: Stored as a plain PHP array (human-readable) instead of base64/unserialize
 * so that:
 *   1. WP.org plugin review can audit patterns without obfuscation concerns.
 *   2. Security researchers can contribute / review signatures easily.
 *   3. False-positive debugging is trivial — each pattern is visible at a glance.
 *   4. No antivirus false-positive risk: patterns describe what attackers write,
 *      not what we write (regex strings are not executable code).
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

return [

    // -------------------------------------------------------------------------
    // CRITICAL - Web Shell / Remote Code Execution
    // -------------------------------------------------------------------------

    'shell_exec_post_get' => [
        'pattern'     => '/shell_exec\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/i',
        'description' => 'shell_exec() called with user-supplied input ($_POST/$_GET) — classic web shell backdoor.',
        'risk'        => 'Critical',
        'confidence'  => 99,
    ],

    'system_post_get' => [
        'pattern'     => '/system\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/i',
        'description' => 'system() called with user-supplied input — command injection backdoor.',
        'risk'        => 'Critical',
        'confidence'  => 99,
    ],

    'passthru_post_get' => [
        'pattern'     => '/passthru\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/i',
        'description' => 'passthru() called with user-supplied input — command execution backdoor.',
        'risk'        => 'Critical',
        'confidence'  => 99,
    ],

    'popen_post_get' => [
        'pattern'     => '/popen\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/i',
        'description' => 'popen() called with user-supplied input — process execution backdoor.',
        'risk'        => 'Critical',
        'confidence'  => 99,
    ],

    'eval_post_request' => [
        'pattern'     => '/eval\s*\(\s*(?:base64_decode\s*\(\s*)?\$_(POST|GET|REQUEST|COOKIE)\s*\[/i',
        'description' => 'eval() with user-supplied input — arbitrary code execution backdoor.',
        'risk'        => 'Critical',
        'confidence'  => 99,
    ],

    'reverse_auth_backdoor' => [
        'pattern'     => '/(?:shell_exec|system|passthru|exec|popen|proc_open)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[\s*[\'\"](cmd|command|c|x|exec|run)[\'\"]\s*\]/i',
        'description' => 'Direct command execution from user input — web shell RAT detected.',
        'risk'        => 'Critical',
        'confidence'  => 99,
    ],

    'auth_key_backdoor' => [
        'pattern'     => '/\$_(POST|GET|REQUEST|COOKIE)\s*\[\s*[\'\"](key|cmd|pass|password|auth|token|secret|backdoor)[\'\"]\s*\].{0,100}(?:shell_exec|system|passthru|exec|popen|proc_open)\s*\(/is',
        'description' => 'Auth-key gated backdoor detected — attacker sends secret key to execute commands.',
        'risk'        => 'Critical',
        'confidence'  => 99,
    ],

    'hidden_post_cmd_pattern' => [
        'pattern'     => '/if\s*\(\s*isset\s*\(\s*\$_POST\s*\[\s*[\'\"](cmd|command|c|x|exec|run|shell)[\'\"]\s*\]\s*\)/i',
        'description' => 'Hidden POST command handler detected — typical web shell entry point.',
        'risk'        => 'Critical',
        'confidence'  => 98,
    ],

    // -------------------------------------------------------------------------
    // CRITICAL - Code Execution via PHP Functions
    // -------------------------------------------------------------------------

    'preg_replace_eval' => [
        'pattern'     => '/preg_replace\s*\(\s*[\'\"]\/.+\/e[\'\"]\s*,/i',
        'description' => 'preg_replace with /e modifier — allows arbitrary code execution (deprecated but still dangerous).',
        'risk'        => 'Critical',
        'confidence'  => 95,
    ],

    'assert_post_get' => [
        'pattern'     => '/assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/i',
        'description' => 'assert() with user-supplied input — code execution backdoor via assert.',
        'risk'        => 'Critical',
        'confidence'  => 97,
    ],

    'create_function_backdoor' => [
        'pattern'     => '/create_function\s*\(\s*[\'\"]\s*[\'\"]\s*,\s*\$_(POST|GET|REQUEST|COOKIE)/i',
        'description' => 'create_function() with user input — runtime PHP code creation backdoor.',
        'risk'        => 'Critical',
        'confidence'  => 96,
    ],

    // -------------------------------------------------------------------------
    // HIGH - File Write / Upload Backdoors
    // -------------------------------------------------------------------------

    'file_put_contents_php' => [
        'pattern'     => '/file_put_contents\s*\(\s*.*\$_(POST|GET|REQUEST|COOKIE)/i',
        'description' => 'file_put_contents with user input — file upload/write backdoor.',
        'risk'        => 'Critical',
        'confidence'  => 95,
    ],

    'fwrite_post_get' => [
        'pattern'     => '/fwrite\s*\(\s*\$\w+\s*,\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/i',
        'description' => 'fwrite() with user-controlled content — arbitrary file write backdoor.',
        'risk'        => 'High',
        'confidence'  => 90,
    ],

    // -------------------------------------------------------------------------
    // HIGH - Obfuscation and Evasion
    // -------------------------------------------------------------------------

    'base64_superglobal_combo' => [
        'pattern'     => '/base64_decode\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SERVER)\s*\[/i',
        'description' => 'base64_decode with superglobal input — obfuscated command injection.',
        'risk'        => 'High',
        'confidence'  => 95,
    ],

    'gzinflate_base64_chain' => [
        'pattern'     => '/gzinflate\s*\(\s*base64_decode\s*\(/i',
        'description' => 'gzinflate(base64_decode()) chain — classic PHP obfuscation dropper.',
        'risk'        => 'High',
        'confidence'  => 90,
    ],

    'str_rot13_eval' => [
        'pattern'     => '/eval\s*\(\s*str_rot13\s*\(/i',
        'description' => 'eval(str_rot13()) — ROT13 encoded payload execution.',
        'risk'        => 'High',
        'confidence'  => 93,
    ],

    // -------------------------------------------------------------------------
    // HIGH - Known Malware Signatures
    // -------------------------------------------------------------------------

    'obfuscated_dropper_chr_explode' => [
        'pattern'     => '/explode\s*\(\s*chr\s*\(\s*\(\s*\d+\s*-\s*\d+\s*\)\s*\)\s*,\s*substr\s*\(/i',
        'description' => 'Obfuscated malware dropper using math-based chr() and explode() to reconstruct payload.',
        'risk'        => 'Critical',
        'confidence'  => 99,
    ],

    'wp_vcd_malware' => [
        'pattern'     => '/wp-includes\/wp-vcd|class-wp-vcd|wp_vcd/i',
        'description' => 'WP-VCD malware signature detected — known WordPress malware family.',
        'risk'        => 'Critical',
        'confidence'  => 99,
    ],

    'auto_admin_creation' => [
        'pattern'     => '/auto-created-admin|admin_pass_reset/i',
        'description' => 'Auto admin creation pattern — backdoor that creates rogue admin accounts.',
        'risk'        => 'Critical',
        'confidence'  => 97,
    ],

    'xxe_entity_injection' => [
        'pattern'     => '/<!ENTITY\s+|SYSTEM\s+[\'"]file:/i',
        'description' => 'XXE (XML External Entity) injection pattern detected.',
        'risk'        => 'High',
        'confidence'  => 92,
    ],

];
