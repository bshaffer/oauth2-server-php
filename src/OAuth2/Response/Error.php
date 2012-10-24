<?php

/**
*
*/
class OAuth2_Response_Error extends OAuth2_Response
{
    public function __construct($statusCode, $error, $errorDescription)
    {
        $parameters = array(
            'error' => $error,
            'error_description' => $errorDescription,
        );

        $httpHeaders = array(
            'Cache-Control' => 'no-store'
        );

        parent::__construct($parameters, $statusCode, $httpHeaders);

        if (!$this->isClientError() && !$this->isServerError()) {
            throw new InvalidArgumentException(sprintf('The HTTP status code is not an error ("%s" given).', $statusCode));
        }
    }

    public function getError()
    {
        return $this->parameters['error'];
    }

    public function getErrorDescription()
    {
        return $this->parameters['error_description'];
    }

    public function getErrorUri()
    {
        return $this->parameters['error_uri'];
    }
}

