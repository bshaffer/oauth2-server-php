<?php

/**
 * @see OAuth2_Controller_TokenControllerInterface
 */
class OAuth2_Controller_TokenController implements OAuth2_Controller_TokenControllerInterface
{
    private $response;
    private $clientAssertionType;
    private $accessToken;
    private $grantTypes;
    private $scopeUtil;

    public function __construct(OAuth2_ResponseType_AccessTokenInterface $accessToken, array $grantTypes = array(), OAuth2_ClientAssertionTypeInterface $clientAssertionType = null, OAuth2_ScopeInterface $scopeUtil = null)
    {
        if (is_null($clientAssertionType)) {
            foreach ($grantTypes as $grantType) {
                if (!$grantType instanceof OAuth2_ClientAssertionTypeInterface) {
                    throw new InvalidArgumentException('You must supply an instance of OAuth2_ClientAssertionTypeInterface or only use grant types which implement OAuth2_ClientAssertionTypeInterface');
                }
            }
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

    public function handleTokenRequest(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response)
    {
        if ($token = $this->grantAccessToken($request, $response)) {
            // @see http://tools.ietf.org/html/rfc6749#section-5.1
            // server MUST disable caching in headers when tokens are involved
            $response->setStatusCode(200);
            $response->addParameters($token);
            $response->addHttpHeaders(array('Cache-Control' => 'no-store', 'Pragma' => 'no-cache'));
        }
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
    public function grantAccessToken(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response)
    {
        if (strtolower($request->server('REQUEST_METHOD')) != 'post') {
            $response->setError(405, 'invalid_request', 'The request method must be POST when requesting an access token', '#section-3.2');
            $response->addHttpHeaders(array('Allow' => 'POST'));
            return null;
        }

        /* Determine grant type from request
         * and validate the request for that grant type
         */
        if (!$grantTypeIdentifier = $request->request('grant_type')) {
            $response->setError(400, 'invalid_request', 'The grant type was not specified in the request');
            return null;
        }
        if (!isset($this->grantTypes[$grantTypeIdentifier])) {
            /* TODO: If this is an OAuth2 supported grant type that we have chosen not to implement, throw a 501 Not Implemented instead */
            $response->setError(400, 'unsupported_grant_type', sprintf('Grant type "%s" not supported', $grantTypeIdentifier));
            return null;
        }

        $grantType = $this->grantTypes[$grantTypeIdentifier];
        if (!$grantType->validateRequest($request, $response)) {
            return null;
        }

        /* Retrieve the client information from the request
         * ClientAssertionTypes allow for grant types which also assert the client data
         * in which case ClientAssertion is handled in the validateRequest method
         *
         * @see OAuth2_GrantType_JWTBearer
         * @see OAuth2_GrantType_ClientCredentials
         */
        if ($grantType instanceof OAuth2_ClientAssertionTypeInterface) {
            $clientId = $grantType->getClientId();
        } else {
            if (!$this->clientAssertionType->validateRequest($request, $response)) {
                return null;
            }
            $clientId = $this->clientAssertionType->getClientId();

            // validate the Client ID (if applicable)
            if (!is_null($storedClientId = $grantType->getClientId()) && $storedClientId != $clientId) {
                $response->setError(400, 'invalid_grant', sprintf('%s doesn\'t exist or is invalid for the client', $grantTypeIdentifier));
                return null;
            }
        }

        /*
         * Validate the scope of the token
         * If the grant type returns a value for the scope,
         * this value must be verified with the scope being requested
         */
        $availableScope = $grantType->getScope();
        if (!$requestedScope = $this->scopeUtil->getScopeFromRequest($request)) {
            $requestedScope = $availableScope ? $availableScope : $this->scopeUtil->getDefaultScope();
        }

        if (($requestedScope && !$this->scopeUtil->scopeExists($requestedScope, $clientId))
            || ($availableScope && !$this->scopeUtil->checkScope($requestedScope, $availableScope))) {
            $response->setError(400, 'invalid_scope', 'An unsupported scope was requested');
            return null;
        }

        return $grantType->createAccessToken($this->accessToken, $clientId, $grantType->getUserId(), $requestedScope);
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
}
