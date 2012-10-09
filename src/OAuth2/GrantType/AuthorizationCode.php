<?php

/**
*
*/
class OAuth2_GrantType_AuthorizationCode implements OAuth2_GrantType_AuthorizationCodeInterface, OAuth2_Response_ProviderInterface
{
    private $storage;
    private $response;

    public function __construct(OAuth2_Storage_AuthorizationCodeInterface $storage, $config = array())
    {
        $this->storage = $storage;
        $this->config = array_merge(array(
            'enforce_redirect' => false,
            'auth_code_lifetime' => 30,
        ), $config);
    }

    public function getIdentifier()
    {
        return 'code';
    }

    public function enforceRedirect()
    {
        return $this->config['enforce_redirect'];
    }

    public function validateRequest($request)
    {
        if (!isset($request->query['code']) || !$request->query['code']) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'Missing parameter: "code" is required');
            return false;
        }

        if ($this->enforceRedirect() && (!isset($request->query['redirect_uri']) || !$request->query['redirect_uri'])){
            $this->response = new OAuth2_Response_Error(400, 'invalid_request', "The redirect URI parameter is required.");
            return false;
        }

        return true;
    }

    public function getTokenDataFromRequest($request)
    {
        if (!$tokenData = $this->storage->getAuthorizationCode($request->query['code'])) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "Authorization code doesn't exist or is invalid for the client");
            return null;
        }
        return $tokenData;
    }

    public function validateTokenData(array $tokenData, array $clientData)
    {
        // Check the code exists
        if ($tokenData === null || $clientData['client_id'] != $tokenData['client_id']) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "Authorization code doesn't exist or is invalid for the client");
            return false;
        }

        // Validate the redirect URI. If a redirect URI has been provided on input, it must be validated
        if ($input["redirect_uri"] && !$this->validateRedirectUri($input["redirect_uri"], $tokenData["redirect_uri"])) {
            $this->response = new OAuth2_Response_Error(400, 'redirect_uri_mismatch', "The redirect URI is missing or do not match");
            return false;
        }

        if ($tokenData["expires"] < time()) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "The authorization code has expired");
            return false;
        }

        // Scope is validated in the client class
        return true;
    }

    /**
     * Handle the creation of auth code.
     *
     * This belongs in a separate factory, but to keep it simple, I'm just
     * keeping it here.
     *
     * @param $client_id
     * Client identifier related to the access token.
     * @param $redirect_uri
     * An absolute URI to which the authorization server will redirect the
     * user-agent to when the end-user authorization step is completed.
     * @param $scope
     * (optional) Scopes to be stored in space-separated string.
     *
     * @ingroup oauth2_section_4
     */
    public function createAuthorizationCode($client_id, $user_id, $redirect_uri, $scope = null)
    {
        $code = $this->generateAuthorizationCode();
        $this->storage->setAuthorizationCode($code, $client_id, $user_id, $redirect_uri, time() + $this->config['auth_code_lifetime'], $scope);
        return $code;
    }

    /**
     * Generates an unique auth code.
     *
     * Implementing classes may want to override this function to implement
     * other auth code generation schemes.
     *
     * @return
     * An unique auth code.
     *
     * @ingroup oauth2_section_4
     */
    protected function generateAuthorizationCode()
    {
        $tokenLen = 40;
        if (file_exists('/dev/urandom')) { // Get 100 bytes of random data
            $randomData = file_get_contents('/dev/urandom', false, null, 0, 100) . uniqid(mt_rand(), true);
        } else {
            $randomData = mt_rand() . mt_rand() . mt_rand() . mt_rand() . microtime(true) . uniqid(mt_rand(), true);
        }
        return substr(hash('sha512', $randomData), 0, $tokenLen);
    }

    public function finishGrantRequest($token)
    {}

    public function getResponse()
    {
        return $this->response;
    }
}
