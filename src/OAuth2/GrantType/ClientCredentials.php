<?php

class OAuth2_GrantType_ClientCredentials implements OAuth2_GrantTypeInterface, OAuth2_Response_ProviderInterface
{
    public function getQuerystringIdentifier()
    {
        return 'client_credentials';
    }

    public function validateRequest($request)
    {
        // This has been done in the server class
        return true;
    }

    public function grantAccessToken(OAuth2_ResponseType_AccessTokenInterface $accessToken, $scopeUtil, $request, array $clientData)
    {
        $scope = $scopeUtil->getScopeFromRequest($request);
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

        // Client Credentials Grant does NOT include a refresh token
        // @see http://tools.ietf.org/html/rfc6749#section-4.4.3
        $includeRefreshToken = false;
        return $accessToken->createAccessToken($clientData['client_id'], null, $scope, $includeRefreshToken);
    }

    public function getResponse()
    {
        return $this->response;
    }
}
