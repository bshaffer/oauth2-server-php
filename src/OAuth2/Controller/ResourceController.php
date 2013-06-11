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

        // Check if we have token data
        if (is_null($token)) {
            return false;
        }

        /**
         * Check scope, if provided
         * If token doesn't have a scope, it's null/empty, or it's insufficient, then throw 403
         * @see http://tools.ietf.org/html/rfc6750#section-3.1
         */
        if ($scope && (!isset($token["scope"]) || !$token["scope"] || !$this->scopeUtil->checkScope($scope, $token["scope"]))) {
            $response->setError(403, 'insufficient_scope', 'The request requires higher privileges than provided by the access token');
            $response->addHttpHeaders(array(
                'WWW-Authenticate' => sprintf('%s realm="%s", scope="%s", error="%s", error_description="%s"',
                    $this->tokenType->getTokenType(),
                    $this->config['www_realm'],
                    $scope,
                    $response->getParameter('error'),
                    $response->getParameter('error_description')
                )
            ));
            return false;
        }

        return (bool) $token;
    }

    public function getAccessTokenData(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response)
    {
        // Get the token parameter
        if ($token_param = $this->tokenType->getAccessTokenParameter($request, $response)) {
            // Get the stored token data (from the implementing subclass)
            // Check we have a well formed token
            // Check token expiration (expires is a mandatory paramter)
            if (!$token = $this->tokenStorage->getAccessToken($token_param)) {
                $response->setError(401, 'invalid_token', 'The access token provided is invalid');
            } else if (!isset($token["expires"]) || !isset($token["client_id"])) {
                $response->setError(401, 'invalid_token', 'Malformed token (missing "expires" or "client_id")');
            } else if (time() > $token["expires"]) {
                $response->setError(401, 'invalid_token', 'The access token provided has expired');
            } else {
                return $token;
            }
        }

        $authHeader = sprintf('%s realm="%s"', $this->tokenType->getTokenType(), $this->config['www_realm']);

        if ($error = $response->getParameter('error')) {
            $authHeader = sprintf('%s, error="%s"', $authHeader, $error);
            if ($error_description = $response->getParameter('error_description')) {
                $authHeader = sprintf('%s, error_description="%s"', $authHeader, $error_description);
            }
        }

        $response->addHttpHeaders(array('WWW-Authenticate' => $authHeader));
        return null;
    }
}
