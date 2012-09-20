<?php

/**
*
*/
class OAuth2_GrantType_UserCredentials implements OAuth2_GrantTypeInterface
{
    private $storage;

    public function __construct(OAuth2_Storage_UserCredentialsInterface $storage)
    {
        $this->storage = $storage;
    }

    public function validateInputParameters(array $parameters)
    {
        if (!isset($parameters["username"]) || !isset($parameters["password"])
            || !$parameters["username"] || !$parameters["password"]) {
            throw new OAuth2_Server_Exception(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_INVALID_REQUEST, 'Missing parameters. "username" and "password" required');
        }

        return true;
    }

    public function getTokenDataFromInputParameters(array $parameters)
    {
        return $this->storage->checkUserCredentials($parameters["username"], $parameters["password"]);
    }

    public function validateTokenData(array $tokenData)
    {
        // Scope is validated in the client class
        return true;
    }
}
