<?php

/**
 * @see OAuth2_Controller_ResourceControllerInterface
 */
class OAuth2_Controller_ResourceController implements OAuth2_Controller_ResourceControllerInterface
{
    private $response;
    private $tokenType;
    private $tokenStorage;
    private $config;
    private $scopeUtil;

    public function __construct(OAuth2_TokenTypeInterface $tokenType, OAuth2_Storage_AccessTokenInterface $tokenStorage, $config = array(), OAuth2_ScopeInterface $scopeUtil = null)
    {
        $this->tokenType = $tokenType;
        $this->tokenStorage = $tokenStorage;

        $this->config = array_merge(array(
            'www_realm' => 'Service',
        ), $config);

        if (is_null($scopeUtil)) {
            $scopeUtil = new OAuth2_Scope();
        }
        $this->scopeUtil = $scopeUtil;
    }

    public function verifyResourceRequest(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response, $scope = null)
    {
        $token = $this->getAccessTokenData($request, $response, $scope);

        // Check scope, if provided
        // If token doesn't have a scope, it's null/empty, or it's insufficient, then throw an error
        if ($scope && (!isset($token["scope"]) || !$token["scope"] || !$this->scopeUtil->checkScope($scope, $token["scope"]))) {
            $response->setError(401, 'insufficient_scope', 'The request requires higher privileges than provided by the access token');
            $response->addHttpHeaders(array('WWW-Authenticate' => sprintf('%s, realm="%s", scope="%s"', $this->tokenType->getTokenType(), $this->config['www_realm'], $scope)));
            return false;
        }

        return (bool) $token;
    }

    public function getAccessTokenData(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response)
    {
        // Get the token parameter
        $token_param = $this->tokenType->getAccessTokenParameter($request, $response);
        if (is_null($token_param)) {
            return null;
        }

        // Get the stored token data (from the implementing subclass)
        // Check we have a well formed token
        // Check token expiration (expires is a mandatory paramter)
        if (!$token = $this->tokenStorage->getAccessToken($token_param)) {
            $response->setError(401, 'invalid_grant', 'The access token provided is invalid', $this->tokenType->getTokenType(), $this->config['www_realm']);
        } else if (!isset($token["expires"]) || !isset($token["client_id"])) {
            $response->setError(401, 'invalid_grant', 'Malformed token (missing "expires" or "client_id")', $this->tokenType->getTokenType(), $this->config['www_realm']);
        } else if (isset($token["expires"]) && time() > $token["expires"]) {
            $response->setError(401, 'invalid_grant', 'The access token provided has expired');
        } else {
            return $token;
        }

        $response->addHttpHeaders(array('WWW-Authenticate' => sprintf('%s, realm="%"', $this->tokenType->getTokenType(), $this->config['www_realm'])));
        return null;
    }
}
