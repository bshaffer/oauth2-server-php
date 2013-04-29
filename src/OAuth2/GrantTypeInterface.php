<?php

interface OAuth2_GrantTypeInterface
{
    public function getQuerystringIdentifier();
    public function validateRequest($request);
    public function grantAccessToken(OAuth2_ResponseType_AccessTokenInterface $accessToken, $scopeUtil, $request, array $clientData);
}
