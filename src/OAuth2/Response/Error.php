<?php

/**
*
*/
class OAuth2_Response_Error extends OAuth2_Response
{
    public function __construct($statusCode, $error, $errorDescription, $errorUri = null)
    {
        $parameters = array(
            'error' => $error,
            'error_description' => $errorDescription,
        );

        if (!is_null($errorUri)) {
            if (strlen($errorUri) > 0 && $errorUri[0] == '#') {
                // we are referencing an oauth bookmark (for brevity)
                $errorUri = 'http://tools.ietf.org/html/draft-ietf-oauth-v2-31' . $errorUri;
            }
            $parameters['error_uri'] = $errorUri;
        }

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

