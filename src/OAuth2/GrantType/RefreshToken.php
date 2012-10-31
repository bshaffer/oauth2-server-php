<?php

/**
*
*/
class OAuth2_GrantType_RefreshToken implements OAuth2_GrantTypeInterface, OAuth2_Response_ProviderInterface
{
    private $storage;
    private $response;
    private $oldRefreshToken;

    public function __construct(OAuth2_Storage_RefreshTokenInterface $storage)
    {
        $this->storage = $storage;
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

    public function finishGrantRequest($token)
    {
        $this->storage->unsetRefreshToken($this->oldRefreshToken);
    }

    public function getResponse()
    {
        return $this->response;
    }
}