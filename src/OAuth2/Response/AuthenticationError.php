<?php

/**
*
*/
class OAuth2_Response_AuthenticationError extends OAuth2_Response_Error
{
    public function __construct($statusCode, $error, $errorDescription, $tokenType, $realm, $scope = null)
    {
        parent::__construct($statusCode, $error, $errorDescription);
        $authHeader = sprintf('%s realm=%s', $tokenType, $realm);
        if ($scope) {
            $authHeader = sprintf('%s, scope=%s', $authHeader, $scope);
        }
        $this->setHttpHeader('WWW-Authenticate', $authHeader);
    }
}

