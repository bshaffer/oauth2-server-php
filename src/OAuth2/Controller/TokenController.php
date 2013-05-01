<?php

/**
 *  @see OAuth2_Controller_TokenControllerInterface
 */
class OAuth2_Controller_TokenController implements OAuth2_Controller_TokenControllerInterface
{
    private $response;
    private $clientAssertionType;
    private $accessToken;
    private $grantTypes;
    private $scopeUtil;

    public function __construct($clientAssertionType = null, OAuth2_ResponseType_AccessTokenInterface $accessToken, array $grantTypes = array(), OAuth2_ScopeInterface $scopeUtil = null)
    {
        if ($clientAssertionType instanceof OAuth2_Storage_ClientCredentialsInterface) {
            // this is for backwards compatibility
            $clientAssertionType = new OAuth2_ClientAssertionType_HttpBasic($clientAssertionType);
        }
        if (!is_null($clientAssertionType) && !$clientAssertionType instanceof OAuth2_ClientAssertionTypeInterface) {
            throw new LogicException('$clientAssertionType must be an instance of OAuth2_Storage_ClientCredentialsInterface, OAuth2_ClientAssertionTypeInterface, or null');
        }
        $this->clientAssertionType = $clientAssertionType;
        $this->accessToken = $accessToken;
        foreach ($grantTypes as $grantType) {
            $this->addGrantType($grantType);
        }

        if (is_null($scopeUtil)) {
            $scopeUtil = new OAuth2_Scope();
        }
        $this->scopeUtil = $scopeUtil;
    }

    public function handleTokenRequest(OAuth2_RequestInterface $request)
    {
        if ($token = $this->grantAccessToken($request)) {
            // @see http://tools.ietf.org/html/rfc6749#section-5.1
            // server MUST disable caching in headers when tokens are involved
            $this->response = new OAuth2_Response($token, 200, array('Cache-Control' => 'no-store', 'Pragma' => 'no-cache'));
        }
        return $this->response;
    }

    /**
     * Grant or deny a requested access token.
     * This would be called from the "/token" endpoint as defined in the spec.
     * You can call your endpoint whatever you want.
     *
     * @param $request - OAuth2_RequestInterface
     * Request object to grant access token
     * @param $grantType - mixed
     * OAuth2_GrantTypeInterface instance or one of the grant types configured in the constructor
     *
     * @throws InvalidArgumentException
     * @throws LogicException
     *
     * @see http://tools.ietf.org/html/rfc6749#section-4
     * @see http://tools.ietf.org/html/rfc6749#section-10.6
     * @see http://tools.ietf.org/html/rfc6749#section-4.1.3
     *
     * @ingroup oauth2_section_4
     */
    public function grantAccessToken(OAuth2_RequestInterface $request)
    {
        if (strtolower($request->server('REQUEST_METHOD')) != 'post') {
            $this->response = new OAuth2_Response_Error(405, 'invalid_request', 'The request method must be POST when requesting an access token', 'http://tools.ietf.org/html/rfc6749#section-3.2');
            $this->response->setHttpHeader( 'Allow', 'POST' );
            return null;
        }

        // Determine grant type from request
        if (!$grantTypeIdentifier = $request->request('grant_type')) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'The grant type was not specified in the request');
            return null;
        }
        if (!isset($this->grantTypes[$grantTypeIdentifier])) {
            /* TODO: If this is an OAuth2 supported grant type that we have chosen not to implement, throw a 501 Not Implemented instead */
            $this->response = new OAuth2_Response_Error(400, 'unsupported_grant_type', sprintf('Grant type "%s" not supported', $grantTypeIdentifier));
            return null;
        }
        $grantType = $this->grantTypes[$grantTypeIdentifier];

        // Hack to see if clientAssertionType is part of the grant type
        // this should change, but right now changing it will break BC
        $clientAssertionType = $grantType instanceof OAuth2_ClientAssertionTypeInterface ? $grantType : $this->clientAssertionType;
        $clientData = $clientAssertionType->getClientData($request);

        /* Retrieve the client information from the request */
        if (!$clientData || !$clientAssertionType->validateClientData($clientData, $grantTypeIdentifier)) {
            if ($clientAssertionType instanceof OAuth2_Response_ProviderInterface && $response = $clientAssertionType->getResponse()) {
                $this->response = $response;
            } else {
                $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'Unable to verify client');
            }
            return null;
        }

        /* Retrieve the token information from the request */
        if (!$tokenData = $grantType->getTokenData($request, $clientData)) {
            if ($grantType instanceof OAuth2_Response_ProviderInterface && $response = $grantType->getResponse()) {
                $this->response = $response;
            } else {
                $this->response = new OAuth2_Response_Error(400, 'invalid_grant', sprintf('Unable to retrieve token for "%s" grant type', $grantTypeIdentifier));
            }
            return null;
        }

        /* Validate the scope of the token */
        if (!isset($tokenData["scope"])) {
            $tokenData["scope"] = $this->scopeUtil->getDefaultScope();
        }

        $scope = $this->scopeUtil->getScopeFromRequest($request);
        // Check scope, if provided
        if (!is_null($scope) && !$this->scopeUtil->checkScope($scope, $tokenData["scope"])) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_scope', 'An unsupported scope was requested.');
            return null;
        }

        $tokenData['user_id'] = isset($tokenData['user_id']) ? $tokenData['user_id'] : null;

        return $grantType->createAccessToken($this->accessToken, $clientData, $tokenData);
    }

    /**
     * addGrantType
     *
     * @param grantType - OAuth2_GrantTypeInterface
     * the grant type to add for the specified identifier
     * @param identifier - string
     * a string passed in as "grant_type" in the response that will call this grantType
     **/
    public function addGrantType(OAuth2_GrantTypeInterface $grantType, $identifier = null)
    {
        if (is_null($identifier) || is_numeric($identifier)) {
            $identifier = $grantType->getQuerystringIdentifier();
        }

        $this->grantTypes[$identifier] = $grantType;
    }

    public function getResponse()
    {
        return $this->response;
    }
}
