<?php

/**
*
*/
class OAuth2_GrantType_AuthorizationCode implements OAuth2_GrantTypeInterface
{
    private $storage;
    public $response;

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
            if (!is_null($this->response)) {
                $this->response->setErrorResponse(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_INVALID_REQUEST, 'Missing parameter. "code" is required');
            }
            return false;
        }

        if ($this->config['enforce_redirect'] && !isset($parameters['redirect_uri']) || !$parameters['redirect_uri']){
            if (!is_null($this->response)) {
                $this->response->setErrorResponse(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_INVALID_REQUEST, "The redirect URI parameter is required.");
            }
            return false;
        }

        return true;
    }

    public function getTokenDataFromRequest($request)
    {
        return $this->storage->getAuthorizationCode($parameters['code']);
    }

    public function validateTokenData(array $tokenData)
    {
        // Check the code exists
        if ($tokenData === null || $client[0] != $tokenData['client_id']) {
            if (!is_null($this->response)) {
                $this->response->setErrorResponse(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_INVALID_GRANT, "Refresh token doesn't exist or is invalid for the client");
            }
            return false;
        }

        // Validate the redirect URI. If a redirect URI has been provided on input, it must be validated
        if ($input["redirect_uri"] && !$this->validateRedirectUri($input["redirect_uri"], $tokenData["redirect_uri"])) {
            if (!is_null($this->response)) {
                $this->response->setErrorResponse(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_REDIRECT_URI_MISMATCH, "The redirect URI is missing or do not match");
            }
            return false;
        }

        if ($tokenData["expires"] < time()) {
            if (!is_null($this->response)) {
                $this->response->setErrorResponse(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_INVALID_GRANT, "The authorization code has expired");
            }
            return false;;
        }

        // Scope is validated in the client class
        return true;
    }

    public function getIdentifier()
    {
        return 'code';
    }
}
