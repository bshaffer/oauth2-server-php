<?php

/**
*
*/
class OAuth2_Response_Error extends OAuth2_Response
{
    public function __construct($statusCode, $error, $errorDescription)
    {
        $responseParameters = array(
            'error' => $error,
            'error_description' => $errorDescription,
        );

        $httpHeaders = array(
            'Cache-Control' => 'no-store'
        );

        parent::__construct($responseParameters, $statusCode, $httpHeaders);

        if (!$this->isClientError() && !$this->isServerError()) {
            throw new InvalidArgumentException(sprintf('The HTTP status code is not an error ("%s" given).', $statusCode));
        }
    }
}

