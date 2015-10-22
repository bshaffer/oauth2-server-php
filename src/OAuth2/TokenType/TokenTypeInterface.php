<?php

namespace OAuth2\TokenType;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

interface TokenTypeInterface
{
    /**
     * Token type identification string
     *
     * ex: "bearer" or "mac"
     */
    public function getTokenType();

    /**
     * Retrieves the token string from the request object
     */
    public function getAccessTokenParameter(RequestInterface $request, ResponseInterface $response);
}
