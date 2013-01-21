<?php

/**
 *  This controller is called when a "resource" is requested.
 *  call verifyAccessRequest in order to determine if the request
 *  contains a valid token.
 *
 *  ex:
 *  > if (!$accessController->verifyAccessRequest(OAuth2_Request::createFromGlobals())) {
 *  >     $accessController->getResponse()->send(); // authorization failed
 *  >     die();
 *  > }
 *  > return json_encode($resource); // valid token!  Send the stuff!
 *
 */
interface OAuth2_Controller_AccessControllerInterface extends OAuth2_Response_ProviderInterface
{
    public function verifyAccessRequest(OAuth2_RequestInterface $request);

    public function getAccessTokenData($token_param, $scope = null);
}
