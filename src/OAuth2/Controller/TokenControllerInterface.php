<?php

namespace OAuth2\Controller;

use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;

/**
 *  This controller is called when a token is being requested.
 *  it is called to handle all grant types the application supports.
 *  It also validates the client's credentials
 *
 *  ex:
 *  > $tokenController->handleTokenRequest(OAuth2\Request::createFromGlobals(), $response = new OAuth2\Response());
 *  > $response->send();
 *
 */
interface TokenControllerInterface
{
    /**
     * handleTokenRequest
     *
     * @param $request
     * OAuth2_RequestInterface - The current http request
     * @param $response
     * OAuth2_ResponseInterface - An instance of OAuth2_ResponseInterface to contain the response data
     *
     */
    public function handleTokenRequest(RequestInterface $request, ResponseInterface $response);

    public function grantAccessToken(RequestInterface $request, ResponseInterface $response);
}
