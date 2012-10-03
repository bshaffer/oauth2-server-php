<?php

/**
*
*/
class OAuth2_GrantType_AuthorizationCode implements OAuth2_GrantTypeInterface, OAuth2_ResponseProviderInterface
{
    private $storage;
    private $response;

    public function __construct(OAuth2_Storage_AuthorizationCodeInterface $storage, $config = array())
    {
        $this->storage = $storage;
        $this->config = array_merge(array(
            'enforce_redirect' => false
        ), $config);
    }

    public function validateRequest($request)
    {
        if (!isset($request->query['code']) || !$request->query['code']) {
            $this->response = new OAuth2_ErrorResponse(400, 'invalid_request', 'Missing parameter: "code" is required');
            return false;
        }

        if ($this->config['enforce_redirect'] && (!isset($request->query['redirect_uri']) || !$request->query['redirect_uri'])){
            $this->response = new OAuth2_ErrorResponse(400, 'invalid_request', "The redirect URI parameter is required.");
            return false;
        }

        return true;
    }

    public function getTokenDataFromRequest($request)
    {
        if (!$tokenData = $this->storage->getAuthorizationCode($request->query['code'])) {
            $this->response = new OAuth2_ErrorResponse(400, 'invalid_grant', "Authorization code doesn't exist or is invalid for the client");
            return null;
        }
        return $tokenData;
    }

    public function validateTokenData(array $tokenData, array $clientData)
    {
        // Check the code exists
        if ($tokenData === null || $clientData['client_id'] != $tokenData['client_id']) {
            $this->response = new OAuth2_ErrorResponse(400, 'invalid_grant', "Authorization code doesn't exist or is invalid for the client");
            return false;
        }

        // Validate the redirect URI. If a redirect URI has been provided on input, it must be validated
        if ($input["redirect_uri"] && !$this->validateRedirectUri($input["redirect_uri"], $tokenData["redirect_uri"])) {
            $this->response = new OAuth2_ErrorResponse(400, 'redirect_uri_mismatch', "The redirect URI is missing or do not match");
            return false;
        }

        if ($tokenData["expires"] < time()) {
            $this->response = new OAuth2_ErrorResponse(400, 'invalid_grant', "The authorization code has expired");
            return false;
        }

        // Scope is validated in the client class
        return true;
    }

    public function finishTokenGrant($token)
    {}

    public function getIdentifier()
    {
        return 'code';
    }

    public function getResponse()
    {
        return $this->response;
    }
}
