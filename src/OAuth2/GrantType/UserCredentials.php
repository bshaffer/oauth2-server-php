<?php

/**
*
*/
class OAuth2_GrantType_UserCredentials implements OAuth2_GrantTypeInterface
{
    private $storage;
    private $userInfo;

    public function __construct(OAuth2_Storage_UserCredentialsInterface $storage)
    {
        $this->storage = $storage;
    }

    public function getQuerystringIdentifier()
    {
        return 'password';
    }

    public function validateRequest(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response)
    {
        if (!$request->request("password") || !$request->request("username")) {
            $response->setError(400, 'invalid_request', 'Missing parameters: "username" and "password" required');
            return null;
        }

        if (!$this->storage->checkUserCredentials($request->request("username"), $request->request("password"))) {
            $response->setError(400, 'invalid_grant', 'Invalid username and password combination');
            return null;
        }

        $userInfo = $this->storage->getUserDetails($request->request("username"));

        // userInfo can be an empty array
        if (false === $userInfo || is_null($userInfo)) {
            $response->setError(400, 'invalid_grant', 'Unable to retrieve user information');
            return null;
        }

        $this->userInfo = $userInfo;

        return true;
    }

    public function getClientId()
    {
        return null;
    }

    public function getUserId()
    {
        return $this->userInfo['user_id'];
    }

    public function getScope()
    {
        return isset($this->userInfo['scope']) ? $this->userInfo['scope'] : null;
    }

    public function createAccessToken(OAuth2_ResponseType_AccessTokenInterface $accessToken, $client_id, $user_id, $scope)
    {
        return $accessToken->createAccessToken($client_id, $user_id, $scope);
    }
}
