<?php

/**
 *  @see OAuth2_Controller_AccessControllerInterface
 */
class OAuth2_Controller_AccessController implements OAuth2_Controller_AccessControllerInterface
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

    public function verifyAccessRequest(OAuth2_RequestInterface $request, $scope = null)
    {
        $token_data = $this->getAccessTokenData($request, $scope);

        return (bool) $token_data;
    }

    public function getAccessTokenData(OAuth2_RequestInterface $request, $scope = null)
    {
        $token_param = $this->tokenType->getAccessTokenParameter($request);
        $this->response = $this->tokenType->getResponse();

        if(!$token_param){
            return null;
        }

        if (!$token_param) { // Access token was not provided
            $this->response = new OAuth2_Response_AuthenticationError(400, 'invalid_request', 'The request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same parameter, uses more than one method for including an access token, or is otherwise malformed', $this->tokenType->getTokenType(), $this->config['www_realm'], $scope);
            return null;
        }

        // Get the stored token data (from the implementing subclass)
        $token = $this->tokenStorage->getAccessToken($token_param);
        if ($token === null) {
            $this->response = new OAuth2_Response_AuthenticationError(401, 'invalid_grant', 'The access token provided is invalid', $this->tokenType->getTokenType(), $this->config['www_realm'], $scope);
            return null;
        }

        // Check we have a well formed token
        if (!isset($token["expires"]) || !isset($token["client_id"])) {
            $this->response = new OAuth2_Response_AuthenticationError(401, 'invalid_grant', 'Malformed token (missing "expires" or "client_id")', $this->tokenType->getTokenType(), $this->config['www_realm'], $scope);
            return null;
        }

        // Check token expiration (expires is a mandatory paramter)
        if (isset($token["expires"]) && time() > $token["expires"]) {
            $this->response = new OAuth2_Response_AuthenticationError(401, 'invalid_grant', 'The access token provided has expired', $this->tokenType->getTokenType(), $this->config['www_realm'], $scope);
            return null;
        }

        // Check scope, if provided
        // If token doesn't have a scope, it's null/empty, or it's insufficient, then throw an error
        if ($scope && (!isset($token["scope"]) || !$token["scope"] || !$this->scopeUtil->checkScope($scope, $token["scope"]))) {
            $this->response = new OAuth2_Response_AuthenticationError(401, 'insufficient_scope', 'The request requires higher privileges than provided by the access token', $this->tokenType->getTokenType(), $this->config['www_realm'], $scope);
            return null;
        }

        return $token;
    }

    public function getResponse()
    {
        return $this->response;
    }
}
