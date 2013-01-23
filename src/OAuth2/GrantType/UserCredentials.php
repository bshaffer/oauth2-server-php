<?php

/**
*
*/
class OAuth2_GrantType_UserCredentials implements OAuth2_GrantTypeInterface, OAuth2_Response_ProviderInterface
{
    private $storage;
    private $response;

    public function __construct(OAuth2_Storage_UserCredentialsInterface $storage)
    {
        $this->storage = $storage;
    }

    public function getQuerystringIdentifier()
    {
        return 'password';
    }

    public function validateRequest($request)
    {
        if (!$request->request("password") || !$request->request("username")) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'Missing parameters: "username" and "password" required');
            return false;
        }

        return true;
    }

    public function getTokenDataFromRequest($request)
    {
        if (!$this->storage->checkUserCredentials($request->request("username"), $request->request("password"))) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', 'Invalid username and password combination');
            return false;
        }

        $tokenData = $this->storage->getUserDetails($request->request("username"));

        // tokenData can be an empty array
        if (false === $tokenData || is_null($tokenData)) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', 'Unable to retrieve user information');
            return false;
        }

        return $tokenData;
    }

    public function validateTokenData($tokenData, array $clientData)
    {
        // Scope is validated in the client class
        return true;
    }

    public function createAccessToken(OAuth2_ResponseType_AccessTokenInterface $accessToken, array $clientData, array $tokenData)
    {
        return $accessToken->createAccessToken($clientData['client_id'], $tokenData['user_id'], $tokenData['scope']);
    }

    public function getResponse()
    {
        return $this->response;
    }
}
