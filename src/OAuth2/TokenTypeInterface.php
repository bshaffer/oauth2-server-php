<?php

interface OAuth2_TokenTypeInterface
{
    public function getTokenType();
    public function getAccessTokenParameter(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response);
}
