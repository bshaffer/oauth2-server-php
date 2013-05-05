<?php

interface OAuth2_ClientAssertionTypeInterface
{
    public function validateRequest(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response);
    public function getClientId();
}
