<?php

namespace OAuth2\Controller;

use OAuth2\ResponseType\AccessTokenInterface;
use OAuth2\ClientAssertionType\ClientAssertionTypeInterface;
use OAuth2\GrantType\GrantTypeInterface;
use OAuth2\ScopeInterface;
use OAuth2\Scope;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;

/**
 * @see OAuth2_Controller_TokenControllerInterface
 */
class TokenController implements TokenControllerInterface
{
    protected $accessToken;
    protected $grantTypes;
    protected $clientAssertionType;
    protected $scopeUtil;

    public function __construct(AccessTokenInterface $accessToken, array $grantTypes = array(), ClientAssertionTypeInterface $clientAssertionType = null, ScopeInterface $scopeUtil = null)
    {
        if (is_null($clientAssertionType)) {
            foreach ($grantTypes as $grantType) {
                if (!$grantType instanceof ClientAssertionTypeInterface) {
                    throw new \InvalidArgumentException('You must supply an instance of OAuth2\ClientAssertionTypeInterface or only use grant types which implement OAuth2\ClientAssertionTypeInterface');
                }
            }
        }
        $this->clientAssertionType = $clientAssertionType;
        $this->accessToken = $accessToken;
        foreach ($grantTypes as $grantType) {
            $this->addGrantType($grantType);
        }

        if (is_null($scopeUtil)) {
            $scopeUtil = new Scope();
        }
        $this->scopeUtil = $scopeUtil;
    }

    public function handleTokenRequest(RequestInterface $request, ResponseInterface $response)
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
     * @param $request - RequestInterface
     * Request object to grant access token
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
    public function grantAccessToken(RequestInterface $request, ResponseInterface $response)
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

        /* Retrieve the client information from the request
         * ClientAssertionTypes allow for grant types which also assert the client data
         * in which case ClientAssertion is handled in the validateRequest method
         *
         * @see OAuth2\GrantType\JWTBearer
         * @see OAuth2\GrantType\ClientCredentials
         */
        if (!$grantType instanceof ClientAssertionTypeInterface) {
            if (!$this->clientAssertionType->validateRequest($request, $response)) {
                return null;
            }
            $clientId = $this->clientAssertionType->getClientId();
        }

        /* Retrieve the grant type information from the request
         * The GrantTypeInterface object handles all validation
         * If the object is an instance of ClientAssertionTypeInterface,
         * That logic is handled here as well
         */
        if (!$grantType->validateRequest($request, $response)) {
            return null;
        }

        if ($grantType instanceof ClientAssertionTypeInterface) {
            $clientId = $grantType->getClientId();
        } else {
            // validate the Client ID (if applicable)
            if (!is_null($storedClientId = $grantType->getClientId()) && $storedClientId != $clientId) {
                $response->setError(400, 'invalid_grant', sprintf('%s doesn\'t exist or is invalid for the client', $grantTypeIdentifier));

                return null;
            }
        }

        /*
         * Validate the scope of the token
         * If the grant type returns a value for the scope,
         * as is the case with the "Authorization Code" grant type,
         * this value must be verified with the scope being requested
         */
        $availableScope = $grantType->getScope();
        if (!$requestedScope = $this->scopeUtil->getScopeFromRequest($request)) {
            if (!$availableScope) {
                if (false === $defaultScope = $this->scopeUtil->getDefaultScope($clientId)) {
                    $response->setError(400, 'invalid_scope', 'This application requires you specify a scope parameter');

                    return null;
                }
            }
            $requestedScope = $availableScope ? $availableScope : $defaultScope;
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
     * @param grantType - OAuth2\GrantTypeInterface
     * the grant type to add for the specified identifier
     * @param identifier - string
     * a string passed in as "grant_type" in the response that will call this grantType
     **/
    public function addGrantType(GrantTypeInterface $grantType, $identifier = null)
    {
        if (is_null($identifier) || is_numeric($identifier)) {
            $identifier = $grantType->getQuerystringIdentifier();
        }

        $this->grantTypes[$identifier] = $grantType;
    }
}
