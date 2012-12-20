<?php

interface OAuth2_Controller_AccessControllerInterface extends OAuth2_Response_ProviderInterface
{
    public function verifyAccessRequest(OAuth2_RequestInterface $request);

    public function getAccessTokenData($token_param, $scope = null);
}