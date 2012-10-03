<?php

/**
*
*/
class OAuth2_Response_Redirect extends OAuth2_Response
{
    public function __construct($url, $statusCode = 302, $error = null, $errorDescription = null, $state = null)
    {
        if (empty($url)) {
            throw new InvalidArgumentException('Cannot redirect to an empty URL.');
        }

        $httpHeaders = array(
            'Location' =>  $url,
        );

        $responseParameters = array();

        if (!is_null($error)) {
            $responseParameters['error'] = $error;
        }

        if (!is_null($errorDescription)) {
            $responseParameters['error_description'] = $errorDescription;
        }

        if (!is_null($state)) {
            $responseParameters['state'] = $state;
        }

        parent::__construct($responseParameters, $statusCode, $httpHeaders);

        if (!$this->isRedirect()) {
            throw new InvalidArgumentException(sprintf('The HTTP status code is not a redirect ("%s" given).', $statusCode));
        }
    }
}

