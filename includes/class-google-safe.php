<?php
namespace Nexura_Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Google_Safe
 * 
 * Google Safe Browsing API integration and warning detection.
 */
class Google_Safe {

    /**
     * Checks a URL against the Google Safe Browsing API.
     *
     * @param string $url The URL to check.
     * @return array Status of the URL.
     */
    public function check_url( $url ) {
        $api_key = get_option( 'NEXURA_google_api_key' );
        
        if ( empty( $api_key ) ) {
            return [
                'error' => true,
                'message' => 'API Key is missing. Please configure it in the Settings tab.'
            ];
        }

        $endpoint = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' . $api_key;

        $body = [
            'client' => [
                'clientId'      => 'nexura-security',
                'clientVersion' => NEXURA_VERSION
            ],
            'threatInfo' => [
                'threatTypes'      => ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                'platformTypes'    => ['ANY_PLATFORM'],
                'threatEntryTypes' => ['URL'],
                'threatEntries'    => [
                    ['url' => $url]
                ]
            ]
        ];

        $response = wp_remote_post( $endpoint, [
            'body'    => wp_json_encode( $body ),
            'headers' => [ 'Content-Type' => 'application/json' ],
            'timeout' => 15
        ]);

        if ( is_wp_error( $response ) ) {
            return [
                'error'   => true,
                'message' => 'Failed to contact Google API: ' . $response->get_error_message()
            ];
        }

        $response_code = wp_remote_retrieve_response_code( $response );
        $response_body = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( $response_code !== 200 ) {
            return [
                'error'   => true,
                'message' => 'API Error: ' . ( isset( $response_body['error']['message'] ) ? $response_body['error']['message'] : 'Unknown error' )
            ];
        }

        if ( isset( $response_body['matches'] ) && ! empty( $response_body['matches'] ) ) {
            return [
                'safe'    => false,
                'details' => $response_body['matches']
            ];
        }

        return [
            'safe'    => true,
            'details' => []
        ];
    }

    /**
     * Checks the main site URL.
     *
     * @return array Status.
     */
    public function check_site() {
        $site_url = get_site_url();
        return $this->check_url( $site_url );
    }

    /**
     * Generates a remediation workflow report if the site is blacklisted.
     *
     * @return array Remediation steps.
     */
    public function get_remediation_workflow() {
        return [
            '1' => 'Review the Malware Scan tab and quarantine any detected suspicious files.',
            '2' => 'Check the File Integrity Monitoring tab for unauthorized file modifications.',
            '3' => 'Ensure all plugins and themes are updated via the Vulnerability Audit tab.',
            '4' => 'Once the site is clean, request a review in Google Search Console.'
        ];
    }
}
