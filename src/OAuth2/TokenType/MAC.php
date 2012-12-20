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

    public function getAccessTokenParameter(OAuth2_RequestInterface $request)
    {
        throw new LogicException("Not supported");

    }
}