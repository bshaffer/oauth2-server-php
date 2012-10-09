<?php

/**
*
*/
class OAuth2_GrantType_RefreshToken implements OAuth2_GrantType_RefreshTokenInterface, OAuth2_Response_ProviderInterface
{
    private $storage;
    private $response;
    private $oldRefreshToken;
    private $config;


    public function __construct(OAuth2_Storage_RefreshTokenInterface $storage, $config = array())
    {
        $this->storage = $storage;
        $this->config = array_merge(array(
            'refresh_token_lifetime' => 1209600,
        ), $config);
    }

    public function getIdentifier()
    {
        return 'refresh_token';
    }

    public function validateRequest($request)
    {
        if (!isset($request->query["refresh_token"]) || !$request->query['refresh_token']) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'Missing parameter: "refresh_token" is required');
            return false;
        }

        return true;
    }

    public function getTokenDataFromRequest($request)
    {
        if (!$stored = $this->storage->getRefreshToken($request->query["refresh_token"])) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', 'Invalid refresh token');
            return false;
        }

        return $stored;
    }

    public function validateTokenData(array $tokenData, array $clientData)
    {
        if ($tokenData === null || $clientData['client_id'] != $tokenData["client_id"]) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', 'Invalid refresh token');
            return false;
        }

        if ($tokenData["expires"] < time()) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', 'Refresh token has expired');
            return false;
        }

        // store the refresh token locally so we can delete it when a new refresh token is generated
        $this->oldRefreshToken = $tokenData["refresh_token"];

        return true;
    }

    public function finishTokenGrant($token)
    {
        $this->storage->unsetRefreshToken($this->oldRefreshToken);
    }

    public function createRefreshToken($refresh_token, $client_id, $user_id, $scope = null)
    {
        $this->storage->setRefreshToken($refresh_token, $client_id, $user_id, time() + $this->getRefreshTokenLifetime(), $scope);
    }

    public function getRefreshTokenLifetime()
    {
        return $this->config['refresh_token_lifetime'];
    }

    public function getResponse()
    {
        return $this->response;
    }
}