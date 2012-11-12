<?php

interface OAuth2_Controller_GrantControllerInterface extends OAuth2_Response_ProviderInterface
{
    /**
     * handleGrantRequest
     *
     * @param $request
     * OAuth2_RequestInterface - The current http request
     *
     **/
    public function handleGrantRequest(OAuth2_RequestInterface $request);

    public function grantAccessToken(OAuth2_RequestInterface $request);

    public function getClientCredentials(OAuth2_RequestInterface $request);
}