<?php

/**
 *  This controller is called when a user should be authorized
 *  by an authorization server.  As OAuth2 does not handle
 *  authorization directly, this controller ensures the request is valid, but
 *  requires the application to determine the value of $is_authorized
 *
 *  ex:
 *  > $user_id = $this->somehowDetermineUserId();
 *  > $is_authorized = $this->somehowDetermineUserAuthorization();
 *  > $response = new OAuth2_Response();
 *  > $authorizeController->handleAuthorizeRequest(
 *  >     OAuth2_Request::createFromGlobals(),
 *  >     $response,
 *  >     $is_authorized,
 *  >     $user_id);
 *  > $response->send();
 *
 */
interface OAuth2_Controller_AuthorizeControllerInterface
{
    /**
     * List of possible authentication response types.
     * The "authorization_code" mechanism exclusively supports 'code'
     * and the "implicit" mechanism exclusively supports 'token'.
     *
     * @var string
     * @see http://tools.ietf.org/html/rfc6749#section-4.1.1
     * @see http://tools.ietf.org/html/rfc6749#section-4.2.1
     */
    const RESPONSE_TYPE_AUTHORIZATION_CODE = 'code';
    const RESPONSE_TYPE_ACCESS_TOKEN = 'token';

    public function handleAuthorizeRequest(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response, $is_authorized, $user_id = null);

    public function validateAuthorizeRequest(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response);
}
