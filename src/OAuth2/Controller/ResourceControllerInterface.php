<?php

/**
 *  This controller is called when a "resource" is requested.
 *  call verifyResourceRequest in order to determine if the request
 *  contains a valid token.
 *
 *  ex:
 *  > if (!$resourceController->verifyResourceRequest(OAuth2_Request::createFromGlobals(), $response = new OAuth2_Response())) {
 *  >     $response->send(); // authorization failed
 *  >     die();
 *  > }
 *  > return json_encode($resource); // valid token!  Send the stuff!
 *
 */
interface OAuth2_Controller_ResourceControllerInterface
{
    public function verifyResourceRequest(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response, $scope = null);

    public function getAccessTokenData(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response);
}
