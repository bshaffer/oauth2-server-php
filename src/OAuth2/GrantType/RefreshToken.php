<?php

/**
*
*/
class OAuth2_GrantType_RefreshToken implements OAuth2_GrantTypeInterface, OAuth2_Response_ProviderInterface
{
    private $storage;
    private $response;
    private $config;
    private $oldRefreshToken;

    public function __construct(OAuth2_Storage_RefreshTokenInterface $storage, $config = array())
    {
        $this->config = array_merge(array(
            'always_issue_new_refresh_token' => false
        ), $config);
        $this->storage = $storage;
    }

    public function getQuerystringIdentifier()
    {
        return 'refresh_token';
    }

    public function getTokenData(OAuth2_RequestInterface $request, array $clientData)
    {
        if (!$request->request("refresh_token")) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'Missing parameter: "refresh_token" is required');
            return null;
        }

        if (!$tokenData = $this->storage->getRefreshToken($request->request("refresh_token"))) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', 'Invalid refresh token');
            return null;
        }

        if ($tokenData === null || $clientData['client_id'] != $tokenData["client_id"]) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', 'Invalid refresh token');
            return null;
        }

        if ($tokenData["expires"] < time()) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', 'Refresh token has expired');
            return null;
        }

        // store the refresh token locally so we can delete it when a new refresh token is generated
        $this->oldRefreshToken = $tokenData["refresh_token"];

        return $tokenData;
    }

    public function createAccessToken(OAuth2_ResponseType_AccessTokenInterface $accessToken, array $clientData, array $tokenData)
    {
        /*
         * It is optional to force a new refresh token when a refresh token is used.
         * However, if a new refresh token is issued, the old one MUST be expired
         * @see http://tools.ietf.org/html/rfc6749#section-6
         */
        $issueNewRefreshToken = $this->config['always_issue_new_refresh_token'];
        $token = $accessToken->createAccessToken($clientData['client_id'], $tokenData['user_id'], $tokenData['scope'], $issueNewRefreshToken);

        if ($issueNewRefreshToken) {
            $this->storage->unsetRefreshToken($this->oldRefreshToken);
        }

        return $token;
    }

    public function getResponse()
    {
        return $this->response;
    }
}
