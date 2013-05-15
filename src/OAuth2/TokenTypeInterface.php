<?php

interface OAuth2_TokenTypeInterface
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
    public function getAccessTokenParameter(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response);
}
