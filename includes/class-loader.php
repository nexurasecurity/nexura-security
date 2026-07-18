<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Loader
 * 
 * Orchestrates the loading and initialization of all core plugin modules.
 */
class Loader {

    /**
     * Initializes the plugin components.
     */
    public function run() {
        $this->init_modules();
    }

    /**
     * Load all modules.
     */
    private function init_modules() {
        $admin = new Admin();
        if ( is_admin() ) {
            $admin->init();
        }
        // Load admin bar notification on both frontend and backend
        add_action( 'admin_bar_menu', [ $admin, 'add_admin_bar_notification' ], 999 );

        // Core engines (Always load)
        $threat_intel = new Global_Threat_Intel();
        $hardening = new Hardening();
        $hardening->apply_rules();
        if ( is_admin() ) {
            $hardening->init_hooks();
        }
        $cron = new Cron();
        $cron->init();

        // Auth & Frontend Security
        $login_protection = new Login_Protection();
        $login_protection->init();
        $two_factor = new Two_Factor_Auth();
        $two_factor->init();
        $pwned_passwords = new Pwned_Passwords();
        $pwned_passwords->init();
        $anti_spam = new Anti_Spam();
        $anti_spam->init();
        $session_manager = new Session_Manager();
        $session_manager->init();
        $magic_link = new Magic_Link();
        $magic_link->init();
        
        $recaptcha = new reCAPTCHA();
        $recaptcha->init();
        
        $login_security = new Login_Security();
        $login_security->init();
        
        $login_security_integrations = new Login_Security_Integrations();
        $login_security_integrations->init();

        // Admin & Background Processes Only
        if ( is_admin() || ( defined( 'DOING_CRON' ) && DOING_CRON ) || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
            $scanner = new Scanner();
            $real_time_scan = new Real_Time_Scan();
            $file_integrity = new File_Integrity();
            $db_backup = new DB_Backup();
            $db_backup->init();
        }

        // REST API
        add_action( 'rest_api_init', [ new Rest_Controller(), 'register_routes' ] );
    }
}
