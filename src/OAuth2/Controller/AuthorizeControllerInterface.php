<?php

interface OAuth2_Controller_AuthorizeControllerInterface extends OAuth2_Response_ProviderInterface
{
    /**
     * List of possible authentication response types.
     * The "authorization_code" mechanism exclusively supports 'code'
     * and the "implicit" mechanism exclusively supports 'token'.
     *
     * @var string
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.1
     */
    const RESPONSE_TYPE_AUTHORIZATION_CODE = 'code';
    const RESPONSE_TYPE_ACCESS_TOKEN = 'token';

    public function handleAuthorizeRequest(OAuth2_RequestInterface $request, $is_authorized, $user_id = null);

    public function validateAuthorizeRequest(OAuth2_RequestInterface $request);
}