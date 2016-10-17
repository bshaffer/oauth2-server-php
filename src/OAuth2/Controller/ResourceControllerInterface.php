<?php

namespace OAuth2\Controller;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

/**
 *  This controller is called when a "resource" is requested.
 *  call verifyResourceRequest in order to determine if the request
 *  contains a valid token.
 *
 *  ex:
 *  > if (!$resourceController->verifyResourceRequest(OAuth2\Request::createFromGlobals(), $response = new OAuth2\Response())) {
 *  >     $response->send(); // authorization failed
 *  >     die();
 *  > }
 *  > return json_encode($resource); // valid token!  Send the stuff!
 *
 */
interface ResourceControllerInterface
{
    public function verifyResourceRequest(RequestInterface $request, ResponseInterface $response,  StreamInterface $stream, $scope = null);

    public function getAccessTokenData(RequestInterface $request, ResponseInterface $response);
}
