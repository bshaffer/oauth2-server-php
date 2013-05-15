<?php

/**
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
class OAuth2_GrantType_RefreshToken implements OAuth2_GrantTypeInterface
{
    private $storage;
    private $config;
    private $refreshToken;

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

    public function validateRequest(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response)
    {
        if (!$request->request("refresh_token")) {
            $response->setError(400, 'invalid_request', 'Missing parameter: "refresh_token" is required');
            return null;
        }

        if (!$refreshToken = $this->storage->getRefreshToken($request->request("refresh_token"))) {
            $response->setError(400, 'invalid_grant', 'Invalid refresh token');
            return null;
        }

        if ($refreshToken["expires"] < time()) {
            $response->setError(400, 'invalid_grant', 'Refresh token has expired');
            return null;
        }

        // store the refresh token locally so we can delete it when a new refresh token is generated
        $this->refreshToken = $refreshToken;

        return true;
    }

    public function getClientId()
    {
        return $this->refreshToken['client_id'];
    }

    public function getUserId()
    {
        return $this->refreshToken['user_id'];
    }

    public function getScope()
    {
        return $this->refreshToken['scope'];
    }

    public function createAccessToken(OAuth2_ResponseType_AccessTokenInterface $accessToken, $client_id, $user_id, $scope)
    {
        /*
         * It is optional to force a new refresh token when a refresh token is used.
         * However, if a new refresh token is issued, the old one MUST be expired
         * @see http://tools.ietf.org/html/rfc6749#section-6
         */
        $issueNewRefreshToken = $this->config['always_issue_new_refresh_token'];
        $token = $accessToken->createAccessToken($client_id, $user_id, $scope, $issueNewRefreshToken);

        if ($issueNewRefreshToken) {
            $this->storage->unsetRefreshToken($this->refreshToken['refresh_token']);
        }

        return $token;
    }
}
