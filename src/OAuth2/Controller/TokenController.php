<?php

namespace OAuth2\Controller;

use OAuth2\ResponseType\AccessTokenInterface;
use OAuth2\ClientAssertionType\ClientAssertionTypeInterface;
use OAuth2\GrantType\GrantTypeInterface;
use OAuth2\GrantType\UserCredentials;
use OAuth2\ScopeInterface;
use OAuth2\Scope;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;
use OAuth2\Storage\ClientInterface;

/**
 * @see OAuth2_Controller_TokenControllerInterface
 */
class TokenController implements TokenControllerInterface
{
    protected $accessToken;
    protected $grantTypes;
    protected $clientAssertionType;
    protected $scopeUtil;
    protected $clientStorage;

    public function __construct(AccessTokenInterface $accessToken, array $grantTypes = array(), ClientAssertionTypeInterface $clientAssertionType = null, ScopeInterface $scopeUtil = null, ClientInterface $clientStorage = null)
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

        $this->clientStorage = $clientStorage;
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

        /* If we have a password (UserCredentials) grant type, attempt to
         * validate it without resorting to HTTP authentication first, and
         * return early if successful.
         *
         * @see http://aaronparecki.com/articles/2012/07/29/1/oauth2-simplified#others
         * @see https://github.com/bshaffer/oauth2-server-php/issues/257
         */
        if ($grantType instanceof UserCredentials) {
            $result = $this->validatePasswordGrantType($grantType, $request, $response);
            switch ($result) {
                case null:
                    // A null result indicates we could not attempt the UserCredentials
                    // validation yet. Continue on.
                    break;
                case false:
                    // Failure to validate user credentials, failure to validate
                    // client allows password grant, or failure to fetch the
                    // requested scope; we're done.
                    return null;
                default:
                    // We have an access token; return it!
                    return $result;
            }
        }

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

        if (false === ($requestedScope = $this->getRequestedScope($clientId, $grantType, $request, $response))) {
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

    /**
     * Attempt to validate a password grant
     *
     * If we do not have client storage composed, or if no client_id was passed
     * in the request, proceed with normal client assertions.
     *
     * Otherwise, attempt to validate the user credentials; if they are valid,
     * check that the specified client_id allows this grant type, and then that
     * the requested scope is valid.
     *
     * If all validations pass, return an access token.
     *
     * @param UserCredentials $grantType
     * @param RequestInterface $request
     * @param ResponseInterface $response
     * @return null|false|array null when no ClientInterface instance and/or client_id is present, indicating a client assertion is necessary; false if we failed to validate; an access token otherwise
     */
    protected function validatePasswordGrantType(UserCredentials $grantType, RequestInterface $request, ResponseInterface $response)
    {
        // If no ClientInterface instance was passed to the constructor, we'll
        // need to do a client assertion.
        if (is_null($this->clientStorage)) {
            return null;
        }

        // If the client_id is not in the POST, then we'll need to do a client
        // assertion
        if (false === ($clientId = $request->request('client_id', false))) {
            return null;
        }

        // Do not bother validating the user credentials if the client does not support the "password" 
        // grant type.
        if (!$this->clientStorage->checkRestrictedGrantType($clientId, 'password')) {
            $response->setError(400, 'invalid_grant', sprintf('%s doesn\'t exist or is invalid for the client', 'password'));
            return false;
        }

        // Attempt to validate the user credentials
        if (!$grantType->validateRequest($request, $response)) {
            return false;
        }

        // Attempt to validate the requested scope
        if (false === ($requestedScope = $this->getRequestedScope($clientId, $grantType, $request, $response))) {
            return false;
        }

        // All is valid - create and return the access token
        return $grantType->createAccessToken($this->accessToken, $clientId, $grantType->getUserId(), $requestedScope);
    }

    /**
     * Validate the scope of the token
     *
     * If the grant type returns a value for the scope,
     * as is the case with the "Authorization Code" grant type,
     * this value must be verified with the scope being requested
     *
     * @param string $clientId
     * @param GrantTypeInterface $grantType
     * @param RequestInterface $request
     * @param ResponseInterface $response
     * @return false|null|string false on failure to resolve scope, null or string scope on success
     */
    protected function getRequestedScope($clientId, GrantTypeInterface $grantType, RequestInterface $request, ResponseInterface $response)
    {
        $availableScope = $grantType->getScope();
        if (!$requestedScope = $this->scopeUtil->getScopeFromRequest($request)) {
            if (!$availableScope) {
                if (false === $defaultScope = $this->scopeUtil->getDefaultScope($clientId)) {
                    $response->setError(400, 'invalid_scope', 'This application requires you specify a scope parameter');

                    return false;
                }
            }
            $requestedScope = $availableScope ? $availableScope : $defaultScope;
        }

        if (($requestedScope && !$this->scopeUtil->scopeExists($requestedScope, $clientId))
            || ($availableScope && !$this->scopeUtil->checkScope($requestedScope, $availableScope))) {
            $response->setError(400, 'invalid_scope', 'An unsupported scope was requested');

            return false;
        }

        return $requestedScope;
    }
}
