<?php

/**
*
*/
class OAuth2_GrantType_AuthorizationCode implements OAuth2_GrantTypeInterface, OAuth2_Response_ProviderInterface
{
    private $storage;
    private $response;
    private $code;

    public function __construct(OAuth2_Storage_AuthorizationCodeInterface $storage)
    {
        $this->storage = $storage;
    }

    public function getQuerystringIdentifier()
    {
        return 'authorization_code';
    }

    public function validateRequest($request)
    {
        if (!$request->request('code')) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'Missing parameter: "code" is required');
            return false;
        }

        return true;
    }

    public function getTokenDataFromRequest($request)
    {
        $this->code = $request->request('code');
        if (!$tokenData = $this->storage->getAuthorizationCode($this->code)) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "Authorization code doesn't exist or is invalid for the client");
            return null;
        }

        /*
         * 4.1.3 - ensure that the "redirect_uri" parameter is present if the "redirect_uri" parameter was included in the initial authorization request
         * @uri - http://tools.ietf.org/html/rfc6749#section-4.1.3
         */
        if (isset($tokenData['redirect_uri']) && $tokenData['redirect_uri']) {
            if (!$request->request('redirect_uri') || urldecode($request->request('redirect_uri')) != $tokenData['redirect_uri']) {
                $this->response = new OAuth2_Response_Error(400, 'redirect_uri_mismatch', "The redirect URI is missing or do not match", "#section-4.1.3");
                return false;
            }
        }

        return $tokenData;
    }

    public function validateTokenData($tokenData, array $clientData)
    {
        // Check the code exists
        if ($tokenData === null || $clientData['client_id'] != $tokenData['client_id']) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "Authorization code doesn't exist or is invalid for the client");
            return false;
        }

        if ($tokenData["expires"] < time()) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "The authorization code has expired");
            return false;
        }

        // Scope is validated in the client class
        return true;
    }

    public function createAccessToken(OAuth2_ResponseType_AccessTokenInterface $accessToken, array $clientData, array $tokenData)
    {
        $this->storage->expireAuthorizationCode($this->code);
        $token = $accessToken->createAccessToken($clientData['client_id'], $tokenData['user_id'], $tokenData['scope']);

        return $token;
    }

    public function getResponse()
    {
        return $this->response;
    }
}
