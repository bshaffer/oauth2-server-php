<?php

namespace OAuth2\Controller;

use OAuth2\ResponseType\AccessTokenInterface;
use OAuth2\ClientAssertionType\ClientAssertionTypeInterface;
use OAuth2\GrantType\GrantTypeInterface;
use OAuth2\ScopeInterface;
use OAuth2\Scope;
use OAuth2\Storage\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

/**
 * @see OAuth2\Controller\TokenControllerInterface
 */
class TokenController implements TokenControllerInterface
{
    protected $accessToken;
    protected $grantTypes;
    protected $clientAssertionType;
    protected $scopeUtil;
    protected $clientStorage;

    public function __construct(AccessTokenInterface $accessToken, ClientInterface $clientStorage, array $grantTypes = array(), ClientAssertionTypeInterface $clientAssertionType = null, ScopeInterface $scopeUtil = null)
    {
        if (is_null($clientAssertionType)) {
            foreach ($grantTypes as $grantType) {
                if (!$grantType instanceof ClientAssertionTypeInterface) {
                    throw new \InvalidArgumentException('You must supply an instance of OAuth2\ClientAssertionType\ClientAssertionTypeInterface or only use grant types which implement OAuth2\ClientAssertionType\ClientAssertionTypeInterface');
                }
            }
        }
        $this->clientAssertionType = $clientAssertionType;
        $this->accessToken = $accessToken;
        $this->clientStorage = $clientStorage;
        foreach ($grantTypes as $grantType) {
            $this->addGrantType($grantType);
        }

        if (is_null($scopeUtil)) {
            $scopeUtil = new Scope();
        }
        $this->scopeUtil = $scopeUtil;
    }

    public function handleTokenRequest(RequestInterface $request, ResponseInterface $response, StreamInterface $stream)
    {
        $errors = null;
        if($stream->getContents()!="") {
          throw new \LogicException("Stream has to be empty");
        }
        if ($token = $this->grantAccessToken($request, $errors)) {
            // @see http://tools.ietf.org/html/rfc6749#section-5.1
            // server MUST disable caching in headers when tokens are involved
            $stream->write(json_encode($token));
            return $response
                ->withStatus(200)
                ->withHeader('Cache-Control', 'no-store')
                ->withHeader('Content-Type', 'application/json')
                ->withHeader('Pragma', 'no-cache')
                ->withBody($stream);
        }

        $stream->write(json_encode(array_filter(array(
            'error' => $errors['code'],
            'error_description' => $errors['description'],
            'error_uri' => $errors['uri'] ?? null,
        ))));
        return $response
            ->withStatus($errors['code'] == 'invalid_method' ? 405 : 400)
            ->withHeader('Content-Type', 'application/json')
            ->withBody($stream);
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
    public function grantAccessToken(RequestInterface $request, &$errors = null)
    {
        if (strtolower($request->getMethod()) != 'post') {
            $errors = array(
                'code' => 'invalid_method',
                'description' => 'The request method must be POST when requesting an access token',
                'uri' => '#section-3.2',
            );

            return false;
        }


        $body = json_decode((string) $request->getBody(), true);

        /**
         * Determine grant type from request
         * and validate the request for that grant type
         */
        if (empty($body['grant_type'])) {
            $errors = array(
                'code' => 'invalid_request',
                'description' => 'The grant type was not specified in the request',
            );

            return false;
        }

        $grantTypeIdentifier = $body['grant_type'];

        if (!isset($this->grantTypes[$grantTypeIdentifier])) {
            /* TODO: If this is an OAuth2 supported grant type that we have chosen not to implement, throw a 501 Not Implemented instead */
            $errors = array(
                'code' => 'unsupported_grant_type',
                'description' => sprintf('Grant type "%s" not supported', $grantTypeIdentifier),
            );

            return false;
        }

        $grantType = $this->grantTypes[$grantTypeIdentifier];


        /**
         * Retrieve the client information from the request
         * ClientAssertionTypes allow for grant types which also assert the client data
         * in which case ClientAssertion is handled in the validateRequest method
         *
         * @see OAuth2\GrantType\JWTBearer
         * @see OAuth2\GrantType\ClientCredentials
         */
        if (!$grantType instanceof ClientAssertionTypeInterface) {
            $this->clientAssertionType->validateRequest($request, $response);
            $clientId = $this->clientAssertionType->getClientId();
        }

        /**
         * Retrieve the grant type information from the request
         * The GrantTypeInterface object handles all validation
         * If the object is an instance of ClientAssertionTypeInterface,
         * That logic is handled here as well
         */
        $grantType->validateRequest($request, $response);


        if ($grantType instanceof ClientAssertionTypeInterface) {
            $clientId = $grantType->getClientId();
            if(empty($clientId)) {
              $errors = array(
                  'code' => 'invalid_client',
                  'description' => 'client ID doesn\'t exists',
              );

              return false;
            }
        } else {
            // validate the Client ID (if applicable)
            if (!is_null($storedClientId = $grantType->getClientId()) && $storedClientId != $clientId) {
                $errors = array(
                    'code' => 'invalid_grant',
                    'description' => sprintf('%s doesn\'t exist or is invalid for the client', $grantTypeIdentifier),
                );

                return false;
            }
        }



        /**
         * Validate the client can use the requested grant type
         */
        if (!$this->clientStorage->checkRestrictedGrantType($clientId, $grantTypeIdentifier)) {
            $errors = array(
                'code' => 'unauthorized_client',
                'description' => 'The grant type is unauthorized for this client_id',
            );

            return false;
        }

        /**
         * Validate the scope of the token
         *
         * requestedScope - the scope specified in the token request
         * availableScope - the scope associated with the grant type
         *  ex: in the case of the "Authorization Code" grant type,
         *  the scope is specified in the authorize request
         *
         * @see http://tools.ietf.org/html/rfc6749#section-3.3
         */

        $requestedScope = $this->scopeUtil->getScopeFromRequest($request);
        $availableScope = $grantType->getScope();

        if ($requestedScope) {
            // validate the requested scope
            if ($availableScope) {
                if (!$this->scopeUtil->checkScope($requestedScope, $availableScope)) {
                    $errors = array(
                        'code' => 'invalid_scope',
                        'description' => 'The scope requested is invalid for this request',
                    );

                    return false;
                }
            } else {
                // validate the client has access to this scope
                if ($clientScope = $this->clientStorage->getClientScope($clientId)) {
                    if (!$this->scopeUtil->checkScope($requestedScope, $clientScope)) {
                        $errors = array(
                            'code' => 'invalid_scope',
                            'description' => 'The scope requested is invalid for this client',
                        );

                        return false;
                    }
                } elseif (!$this->scopeUtil->scopeExists($requestedScope)) {
                    $errors = array(
                        'code' => 'invalid_scope',
                        'description' => 'An unsupported scope was requested',
                    );

                    return false;
                }
            }
        } elseif ($availableScope) {
            // use the scope associated with this grant type
            $requestedScope = $availableScope;
        } else {
            // use a globally-defined default scope
            $defaultScope = $this->scopeUtil->getDefaultScope($clientId);

            // "false" means default scopes are not allowed
            if (false === $defaultScope) {
                $errors = array(
                    'code' => 'invalid_scope',
                    'description' => 'An unsupported scope was requested',
                );

                return false;
            }

            $requestedScope = $defaultScope;
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
     */
    public function addGrantType(GrantTypeInterface $grantType, $identifier = null)
    {
        if (is_null($identifier) || is_numeric($identifier)) {
            $identifier = $grantType->getQuerystringIdentifier();
        }

        $this->grantTypes[$identifier] = $grantType;
    }

    public function handleRevokeRequest(RequestInterface $request, ResponseInterface $response)
    {
        $errors = null;
        $body = new Stream('php://temp', 'rw');
        if ($this->revokeToken($request, $errors)) {
            $body->write(json_encode(array('revoked' => true)));
            $response
                ->withStatus(200)
                ->withBody($body);
        } else {
            $body->write(json_encode(array_filter(array(
                'error' => $errors['error'],
                'error_description' => $errors['description'],
                'error_uri' => $errors['uri'],
            ))));
            $response
                ->withStatus(isset($errors['status_code']) ? $errors['status_code'] : 400)
                ->withHeader('Cache-Control', 'no-store')
                ->withBody($body);

            if (isset($errors['headers'])) {
                foreach ($errors['headers'] as $key => $value) {
                    $response = $response->withHeader($key, $value);
                }
            }
        }

        return $response
            ->withHeader('Content-Type', 'application/json');
    }

    /**
     * Revoke a refresh or access token. Returns true on success and when tokens are invalid
     *
     * Note: invalid tokens do not cause an error response since the client
     * cannot handle such an error in a reasonable way.  Moreover, the
     * purpose of the revocation request, invalidating the particular token,
     * is already achieved.
     *
     * @param RequestInterface $request
     * @param ResponseInterface $response
     * @return bool|null
     */
    public function revokeToken(RequestInterface $request, &$errors = null)
    {
        $params = json_decode((string) $request->getBody(), true);
        if (strtolower($request->getHeaderLine('REQUEST_METHOD')) != 'post') {
            $errors = array(
                'error' => 'invalid_request',
                'description' => 'The request method must be POST when revoking an access token',
                'uri' => 'http://tools.ietf.org/html/rfc6749#section-3.2',
                'status_code' => 405,
                'headers' => array('Accept' => 'POST'),
            );

            return;
        }

        $token_type_hint = isset($params['token_type_hint']) ? $params['token_type_hint'] : null;
        if (!in_array($token_type_hint, array(null, 'access_token', 'refresh_token'), true)) {
            $errors = array(
                'error' => 'invalid_request',
                'description' => 'Token type hint must be either \'access_token\' or \'refresh_token\''
            );

            return;
        }

        $token = $request->request('token');
        if ($token === null) {
            $errors = array(
                'error' => 'invalid_request',
                'description' => 'Missing token parameter to revoke'
            );

            return;
        }

        // @todo remove this check for v2.0
        if (!method_exists($this->accessToken, 'revokeToken')) {
            $class = get_class($this->accessToken);
            throw new \RuntimeException("AccessToken {$class} does not implement required revokeToken method");
        }

        $this->accessToken->revokeToken($token, $token_type_hint);

        return true;
    }
}
