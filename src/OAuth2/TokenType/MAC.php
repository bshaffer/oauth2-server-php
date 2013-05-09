<?php

/**
* This is not yet supported!
*/
class OAuth2_TokenType_MAC implements OAuth2_TokenTypeInterface
{
    public function getTokenType()
    {
        return 'mac';
    }

    public function getAccessTokenParameter(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response)
    {
        throw new LogicException("Not supported");

    }
}
