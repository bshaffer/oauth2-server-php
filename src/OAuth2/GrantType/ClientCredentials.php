<?php

class OAuth2_GrantType_ClientCredentials implements OAuth2_GrantTypeInterface
{
    public function getIdentifier()
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

    public function validateTokenData(array $tokenData, array $clientData)
    {
        // Scope is validated in the client class
        return true;
    }

    public function finishGrantRequest($token)
    {}
}