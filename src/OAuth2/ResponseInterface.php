<?php

namespace OAuth2;

/**
 * Interface which represents an object response.  Meant to handle and display the proper OAuth2 Responses
 * for errors and successes
 *
 * @see \OAuth2\Response
 */
interface ResponseInterface
{
    /**
     * @param array $parameters
     */
    public function addParameters(array $parameters);

    /**
     * @param array $httpHeaders
     */
    public function addHttpHeaders(array $httpHeaders);

    /**
     * @param int $statusCode
     */
    public function setStatusCode(int $statusCode);

    /**
     * @param int    $statusCode
     * @param string $name
     * @param string $description
     * @param string $uri
     * @return mixed
     */
    public function setError(int $statusCode, string $name, string $description = null, string $uri = null): mixed;

    /**
     * @param int    $statusCode
     * @param string $url
     * @param string $state
     * @param string $error
     * @param string $errorDescription
     * @param string $errorUri
     * @return mixed
     */
    public function setRedirect(int $statusCode, string $url, string $state = null, string $error = null, string $errorDescription = null, string $errorUri = null): mixed;

    /**
     * @param string $name
     * @return mixed
     */
    public function getParameter(string $name): mixed;
}
