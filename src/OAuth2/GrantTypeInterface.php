<?php

interface OAuth2_GrantTypeInterface
{
    public function getQuerystringIdentifier();
    public function getTokenDataFromRequest(OAuth2_RequestInterface $request, array $clientData);
    // public function validateScope(array $tokenData, OAuth2_ScopeInterface $scopeUtil);
    public function createAccessToken(OAuth2_ResponseType_AccessTokenInterface $accessToken, array $clientData, array $tokenData);
}
