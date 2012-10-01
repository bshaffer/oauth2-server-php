<?php

/**
*
*/
class OAuth2_GrantType_UserCredentials implements OAuth2_GrantTypeInterface
{
    private $storage;
    public $response;

    public function __construct(OAuth2_Storage_UserCredentialsInterface $storage)
    {
        $this->storage = $storage;
    }

    public function validateRequest($request)
    {
        if (!isset($request->query["username"]) || !isset($request->query["password"])
            || !$request->query["username"] || !$request->query["password"]) {
            if (!is_null($this->response)) {
                $this->response = new OAuth2_ErrorResponse(400, 'invalid_request', 'Missing parameters: "username" and "password" required');
            }

            return false;
        }

        return true;
    }

    public function getTokenDataFromRequest($request)
    {
        return $this->storage->checkUserCredentials($request->query["username"], $request->query["password"]);
    }

    public function validateTokenData(array $tokenData)
    {
        // Scope is validated in the client class
        return true;
    }

    public function getIdentifier()
    {
        return 'password';
    }
}
