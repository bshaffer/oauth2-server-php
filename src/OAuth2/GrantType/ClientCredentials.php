<?php

class OAuth2_GrantType_ClientCredentials implements OAuth2_GrantTypeInterface
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

    public function getTokenDataFromRequest($request)
    {
        // the only piece to pull is the "scope" parameter
        $scope = $request->headers('REQUEST_METHOD') == 'POST' ? $request->request('scope') : $request->query('scope');
        return array(
            "scope" => $scope
        );
    }

    public function validateTokenData($tokenData, array $clientData)
    {
        // Scope is validated in the client class
        return true;
    }

    public function createAccessToken(OAuth2_ResponseType_AccessTokenInterface $accessToken, array $clientData, array $tokenData)
    {
        /*
         * Client Credentials Grant does NOT include a refresh token
         * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-4.4.3
         */
        $includeRefreshToken = false;
        return $accessToken->createAccessToken($clientData['client_id'], $tokenData['user_id'], $tokenData['scope'], $includeRefreshToken);
    }
}