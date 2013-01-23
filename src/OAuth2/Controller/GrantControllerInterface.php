<?php

/**
 *  This controller is called when a token is being requested.
 *  it is called to handle all grant types the application supports.
 *  It also validates the client's credentials
 *
 *  ex:
 *  > $response = $grantController->handleGrantRequest(OAuth2_Request::createFromGlobals());
 *  > $response->send();
 *
 */
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
