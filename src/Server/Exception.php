<?php

/**
 * OAuth2 errors that require termination of OAuth2 due to
 * an error.
 *
 */
class OAuth2_Server_Exception extends Exception {
    
    protected $httpCode;
    protected $errorData = array();

    /**
     * @param $http_status_code
     * HTTP status code message as predefined.
     * @param $error
     * A single error code.
     * @param $error_description
     * (optional) A human-readable text providing additional information,
     * used to assist in the understanding and resolution of the error
     * occurred.
     */
    public function __construct($http_status_code, $error, $error_description = NULL) 
    {
        parent::__construct($error);
        
        $this->httpCode = $http_status_code;
        
        $this->errorData['error'] = $error;
        if ($error_description) {
            $this->errorData['error_description'] = $error_description;
        }
    }

    /**
     * @return string 
     */
    public function getDescription() 
    {
        return isset($this->errorData['error_description']) ? $this->errorData['error_description'] : null;
    }

    /**
     * @return string 
     */
    public function getHttpCode() 
    {
        return $this->httpCode;
    }

    /**
     * Send out error message in JSON.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     *
     * @ingroup oauth2_error
     */
    public function sendHttpResponse() 
    {
        header("HTTP/1.1 " . $this->httpCode);
        foreach ($this->getHeaders() as $header) {
            header($header);
        }
        echo (string) $this;
        exit();
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
        return array(
            "Content-Type: application/json",
            "Cache-Control: no-store"
        );
    }

    /**
     * @see Exception::__toString()
     */
    public function __toString() 
    {
        return json_encode($this->errorData);
    }
}
