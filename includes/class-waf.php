<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WAF
 * 
 * Web Application Firewall to block SQLi, XSS, RCE, LFI/RFI, and Traversal.
 */
class WAF {

    public function init() {
        // Protect REST API (Application Layer WAF)
        // Now handled by REST_Security_Free class
    }
}
