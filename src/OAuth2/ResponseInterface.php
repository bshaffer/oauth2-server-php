<?php

/**
*
*/
interface OAuth2_ResponseInterface
{
    public function addParameters(array $parameters);
    public function addHttpHeaders(array $httpHeaders);
    public function setStatusCode($statusCode);
    public function setError($statusCode, $name, $description = null, $uri = null);
    public function setRedirect($statusCode = 302, $url, $state = null, $error = null, $errorDescription = null, $errorUri = null);
}