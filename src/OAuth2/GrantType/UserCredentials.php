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

    public function grantAccessToken(OAuth2_ResponseType_AccessTokenInterface $accessToken, $scopeUtil, $request, array $clientData)
    {
        if (!$this->storage->checkUserCredentials($request->request("username"), $request->request("password"))) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', 'Invalid username and password combination');
            return null;
        }

        $userInfo = $this->storage->getUserDetails($request->request("username"));
        // $userInfo can be an empty array.
        if (false === $userInfo || is_null($userInfo)) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', 'Unable to retrieve user information');
            return null;
        }

        $scope = $this->scopeUtil->getScopeFromRequest($request);
        // A scope was provided in the request. Validate that it exists.
        if ($scope && !$scopeUtil->scopeExists($scope, $clientData['client_id'])) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_scope', 'An unsupported scope was requested.');
            return null;
        }
        // No scope provided. Fallback to a default.
        if (!$scope) {
            $scope = $scopeUtil->getDefaultScope();
            // No default scope found. Fail the request, per spec.
            if (!$scope) {
                $this->response = new OAuth2_Response_Error(400, 'invalid_scope', 'An unsupported scope was requested.');
                return null;
            }
        }

        return $accessToken->createAccessToken($clientData['client_id'], $userInfo['user_id'], $scope);
    }

    public function getResponse()
    {
        return $this->response;
    }
}
