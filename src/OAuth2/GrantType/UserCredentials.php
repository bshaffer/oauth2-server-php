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

    public function getIdentifier()
    {
        return 'password';
    }

    public function validateRequest($request)
    {
        if (!isset($request->query["username"]) || !isset($request->query["password"]) || !$request->query["username"] || !$request->query["password"]) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'Missing parameters: "username" and "password" required');
            return false;
        }

        return true;
    }

    public function getTokenDataFromRequest($request)
    {
        if (!$tokenData = $this->storage->checkUserCredentials($request->query["username"], $request->query["password"])) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', 'Invalid username and password combination');
            return false;
        }

        return $tokenData;
    }

    public function validateTokenData(array $tokenData, array $clientData)
    {
        // Scope is validated in the client class
        return true;
    }

    public function finishGrantRequest($token)
    {}

    public function getResponse()
    {
        return $this->response;
    }
}
