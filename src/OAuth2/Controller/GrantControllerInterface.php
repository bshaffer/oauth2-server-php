<?php

interface OAuth2_Controller_GrantControllerInterface extends OAuth2_Response_ProviderInterface
{
    public function handleGrantRequest(OAuth2_Request $request, $grantType = null);

    public function grantAccessToken(OAuth2_Request $request, $grantType = null);

    public function getClientCredentials(OAuth2_Request $request);
}