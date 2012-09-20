<?php

/**
 * Send an error header with the given realm and an error, if provided.
 * Suitable for the bearer token type.
 *
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-04#section-2.4
 *
 * @ingroup oauth2_error
 */
class OAuth2_Authenticate_Exception extends OAuth2_Server_Exception 
{
    
    protected $header;

    /**
     * 
     * @param $http_status_code
     * HTTP status code message as predefined.
     * @param $error
     * The "error" attribute is used to provide the client with the reason
     * why the access request was declined.
     * @param $error_description
     * (optional) The "error_description" attribute provides a human-readable text
     * containing additional information, used to assist in the understanding
     * and resolution of the error occurred.
     * @param $scope
     * A space-delimited list of scope values indicating the required scope
     * of the access token for accessing the requested resource.
     */
    public function __construct($httpCode, $error, $error_description = NULL, $scope = NULL, $tokenType = 'bearer', $realm = 'Service')
    {
        parent::__construct($httpCode, $error, $error_description);
        
        if ($scope) {
            $this->errorData['scope'] = $scope;
        }
        
        // Build header
        $this->header = sprintf('WWW-Authenticate: %s realm="%s"', ucwords($tokenType), $realm);
        foreach ( $this->errorData as $key => $value ) {
            $this->header .= ", $key=\"$value\"";
        }
    }

    /**
     * Send out HTTP headers for JSON.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     *
     * @ingroup oauth2_section_5
     */
    protected function getHeaders() 
    {
        return array($this->header);
    }
}