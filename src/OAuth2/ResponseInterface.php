<?php

namespace OAuth2;

/**
 * Interface which represents an object response.  Meant to handle and display the proper OAuth2 Responses
 * for errors and successes
 *
 * @see OAuth2_Response
 */
interface ResponseInterface
{
    public function addParameters(array $parameters);

    public function addHttpHeaders(array $httpHeaders);

    public function setStatusCode($statusCode);

    public function setError($statusCode, $name, $description = null, $uri = null);

    public function setRedirect($statusCode = 302, $url, $state = null, $error = null, $errorDescription = null, $errorUri = null);

    public function getParameter($name);
}