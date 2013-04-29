<?php

/**
*
*/
class OAuth2_GrantType_RefreshToken implements OAuth2_GrantTypeInterface, OAuth2_Response_ProviderInterface
{
    private $storage;
    private $response;
    private $config;

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

    public function validateRequest($request)
    {
        if (!$request->request("refresh_token")) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'Missing parameter: "refresh_token" is required');
            return false;
        }

        return true;
    }

    public function grantAccessToken(OAuth2_ResponseType_AccessTokenInterface $accessToken, $scopeUtil, $request, array $clientData)
    {
        $refreshToken = $this->storage->getRefreshToken($request->request("refresh_token"));
        if ($refreshToken === null || $clientData['client_id'] != $refreshToken["client_id"]) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', 'Invalid refresh token');
            return null;
        }

        // Validate expiration.
        if ($refreshToken["expires"] < time()) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', 'Refresh token has expired');
            return null;
        }

        // Validate scope.
        // "The requested scope MUST NOT include any scope not originally
        // granted by the resource owner, and if omitted is treated as equal to
        // the scope originally granted by the resource owner."
        $scope = $scopeUtil->getScopeFromRequest($request);
        if (!is_null($scope) && !$scopeUtil->checkScope($scope, $refreshToken["scope"])) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_scope', 'An unsupported scope was requested.');
            return null;
        }
        if (empty($scope)) {
            $scope = $refreshToken['scope'];
        }

        /*
         * It is optional to force a new refresh token when a refresh token is used.
         * However, if a new refresh token is issued, the old one MUST be expired
         * @see http://tools.ietf.org/html/rfc6749#section-6
         */
        $issueNewRefreshToken = $this->config['always_issue_new_refresh_token'];
        $token = $accessToken->createAccessToken($clientData['client_id'], $refreshToken['user_id'], $refreshToken['scope'], $issueNewRefreshToken);
        // A new refresh token was issued. Remove the old one.
        if ($issueNewRefreshToken) {
            $this->storage->unsetRefreshToken($refreshToken["refresh_token"]);
        }

        return $token;
    }

    public function getResponse()
    {
        return $this->response;
    }
}
