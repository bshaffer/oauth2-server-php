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
}