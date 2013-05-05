<?php

interface OAuth2_GrantTypeInterface
{
    public function validateRequest(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response);
    public function getUserId();
    public function getScope();
    public function getClientId();
    public function createAccessToken(OAuth2_ResponseType_AccessTokenInterface $accessToken, $client_id, $user_id, $scope);
}
