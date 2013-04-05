<?php

/**
* Service class for OAuth
* This class serves only to wrap the other Controller classes
* @see OAuth2_Controller_ResourceController
* @see OAuth2_Controller_AuthorizeController
* @see OAuth2_Controller_TokenController
*/
class OAuth2_Server implements OAuth2_Controller_ResourceControllerInterface,
    OAuth2_Controller_AuthorizeControllerInterface, OAuth2_Controller_TokenControllerInterface
{
    // misc properties
    protected $response;
    protected $config;
    protected $storages;

    // servers
    protected $resourceController;
    protected $authorizeController;
    protected $tokenController;

    // config classes
    protected $responseTypes;
    protected $grantTypes;
    protected $accessTokenResponseType;
    protected $scopeUtil;

    protected $storageMap = array(
        'access_token' => 'OAuth2_Storage_AccessTokenInterface',
        'authorization_code' => 'OAuth2_Storage_AuthorizationCodeInterface',
        'client_credentials' => 'OAuth2_Storage_ClientCredentialsInterface',
        'client' => 'OAuth2_Storage_ClientInterface',
        'refresh_token' => 'OAuth2_Storage_RefreshTokenInterface',
        'user_credentials' => 'OAuth2_Storage_UserCredentialsInterface',
        'jwt_bearer' => 'OAuth2_Storage_JWTBearerInterface',
    );
    protected $responseTypeMap = array(
        'token' => 'OAuth2_ResponseType_AccessTokenInterface',
        'code' => 'OAuth2_ResponseType_AuthorizationCodeInterface',
    );

    /**
     * @param mixed $storage
     * array - array of Objects to implement storage
     * OAuth2_Storage object implementing all required storage types (ClientCredentialsInterface and AccessTokenInterface as a minimum)
     *
     * @param array $config
     * specify a different token lifetime, token header name, etc
     *
     * @param array $grantTypes
     * An array of OAuth2_GrantTypeInterface to use for granting access tokens
     *
     * @param array $responseTypes
     * Response types to use.  array keys should be "code" and and "token" for
     * Access Token and Authorization Code response types
     *
     * @param OAuth2_ResponseType_AccessTokenInterface $accessTokenResponseType
     * Response type to use for access token
     *
     * @return
     * TRUE if everything in required scope is contained in available scope,
     * and FALSE if it isn't.
     *
     * @see http://tools.ietf.org/html/rfc6749#section-7
     *
     * @ingroup oauth2_section_7
     */
    public function __construct($storage = array(), array $config = array(), array $grantTypes = array(), array $responseTypes = array(), OAuth2_ResponseType_AccessTokenInterface $accessTokenResponseType = null, OAuth2_ScopeInterface $scopeUtil = null)
    {
        $storage = is_array($storage) ? $storage : array($storage);
        $this->storages = array();
        foreach ($storage as $key => $service) {
            $this->addStorage($service, $key);
        }

        // merge all config values.  These get passed to our controller objects
        $this->config = array_merge(array(
            'token_type'               => 'bearer',
            'access_lifetime'          => 3600,
            'www_realm'                => 'Service',
            'token_param_name'         => 'access_token',
            'token_bearer_header_name' => 'Bearer',
            'enforce_state'            => false,
            'allow_implicit'           => false,
        ), $config);

        foreach ($responseTypes as $key => $responseType) {
            $this->addResponseType($responseType, $key);
        }
        foreach ($grantTypes as $key => $grantType) {
            $this->addGrantType($grantType, $key);
        }
        $this->accessTokenResponseType = $accessTokenResponseType;
        $this->scopeUtil = $scopeUtil;
    }

    public function getResourceController()
    {
        if (is_null($this->resourceController)) {
            if (is_null($this->config['token_type'])) {
                $this->config['token_type'] = 'bearer';
            }
            $tokenType = null;
            if ($this->config['token_type'] == 'bearer') {
                $config = array_intersect_key($this->config, array_flip(explode(' ', 'token_param_name token_bearer_header_name')));
                $tokenType = new OAuth2_TokenType_Bearer($config);
            } elseif ($this->config['token_type'] == 'mac') {
                $tokenType = new OAuth2_TokenType_MAC();
            } else {
                throw new LogicException('unrecognized token type: '.$this->config['token_type']);
            }
            if (!isset($this->storages['access_token'])) {
                throw new LogicException("You must supply a storage object implementing OAuth2_Storage_AccessTokenInterface to use the access server");
            }
            $config = array_intersect_key($this->config, array('www_realm' => ''));
            $this->resourceController = new OAuth2_Controller_ResourceController($tokenType, $this->storages['access_token'], $config, $this->scopeUtil);
        }
        return $this->resourceController;
    }

    public function getAuthorizeController()
    {
        if (is_null($this->authorizeController)) {
            if (!isset($this->storages['client'])) {
                throw new LogicException("You must supply a storage object implementing OAuth2_Storage_ClientInterface to use the authorize server");
            }
            if (0 == count($this->responseTypes)) {
                $this->responseTypes = $this->getDefaultResponseTypes();
            }
            $config = array_intersect_key($this->config, array_flip(explode(' ', 'allow_implicit enforce_state')));
            $this->authorizeController = new OAuth2_Controller_AuthorizeController($this->storages['client'], $this->responseTypes, $config, $this->scopeUtil);
        }
        return $this->authorizeController;
    }

    public function getTokenController()
    {
        if (is_null($this->tokenController)) {
            if (!isset($this->storages['client_credentials'])) {
                throw new LogicException("You must supply a storage object implementing OAuth2_Storage_ClientCredentialsInterface to use the grant server");
            }
            if (is_null($this->accessTokenResponseType)) {
                if (isset($this->responseTypes['access_token'])) {
                    $this->accessTokenResponseType = $this->responseTypes['access_token'];
                } else {
                    if (!isset($this->storages['access_token'])) {
                        throw new LogicException("You must supply a storage object implementing OAuth2_Storage_AccessTokenInterface to use the grant server");
                    }
                    $refreshStorage = null;
                    if (isset($this->storages['refresh_token'])) {
                        $refreshStorage = $this->storages['refresh_token'];
                    }
                    $config = array_intersect_key($this->config, array_flip(explode(' ', 'token_type access_lifetime refresh_token_lifetime')));
                    $this->accessTokenResponseType = new OAuth2_ResponseType_AccessToken($this->storages['access_token'], $refreshStorage, $config);
                }
            }
            if (0 == count($this->grantTypes)) {
                $this->grantTypes = $this->getDefaultGrantTypes();
            }
            $this->tokenController = new OAuth2_Controller_TokenController($this->storages['client_credentials'], $this->accessTokenResponseType, $this->grantTypes, $this->scopeUtil);
        }
        return $this->tokenController;
    }

    protected function getDefaultResponseTypes()
    {
        $responseTypes = array();
        if (isset($this->storages['access_token'])) {
            $refreshStorage = null;
            if (isset($this->storages['refresh_token'])) {
                $refreshStorage = $this->storages['refresh_token'];
            }
            $config = array_intersect_key($this->config, array_flip(explode(' ', 'token_type access_lifetime refresh_token_lifetime')));
            $responseTypes['token'] = new OAuth2_ResponseType_AccessToken($this->storages['access_token'], $refreshStorage, $config);
        }

        if (isset($this->storages['authorization_code'])) {
            $config = array_intersect_key($this->config, array_flip(explode(' ', 'enforce_redirect auth_code_lifetime')));
            $responseTypes['code'] = new OAuth2_ResponseType_AuthorizationCode($this->storages['authorization_code'], $config);
        }

        if (count($responseTypes) == 0) {
            throw new LogicException("You must supply an array of response_types in the constructor or implement a OAuth2_Storage_AccessTokenInterface or OAuth2_Storage_AuthorizationCodeInterface storage object");
        }

        return $responseTypes;
    }

    protected function getDefaultGrantTypes()
    {
        $grantTypes = array();

        if (isset($this->storages['user_credentials'])) {
            $grantTypes['password'] = new OAuth2_GrantType_UserCredentials($this->storages['user_credentials']);
        }

        if (isset($this->storages['client_credentials'])) {
            $grantTypes['client_credentials'] = new OAuth2_GrantType_ClientCredentials($this->storages['client_credentials']);
        }

        if (isset($this->storages['refresh_token'])) {
            $grantTypes['refresh_token'] = new OAuth2_GrantType_RefreshToken($this->storages['refresh_token']);
        }

        if (isset($this->storages['authorization_code'])) {
            $grantTypes['authorization_code'] = new OAuth2_GrantType_AuthorizationCode($this->storages['authorization_code']);
        }

        if (isset($this->storages['jwt_bearer'])) {
            $grantTypes['jwt_bearer'] = new OAuth2_GrantType_JWTBearer($this->storages['jwt_bearer']);
        }

        if (count($grantTypes) == 0) {
            throw new LogicException("Unable to build default grant types - You must supply an array of grant_types in the constructor");
        }

        return $grantTypes;
    }

    /**
     * Grant or deny a requested access token.
     * This would be called from the "/token" endpoint as defined in the spec.
     * Obviously, you can call your endpoint whatever you want.
     *
     * @param $request - OAuth2_Request
     * Request object to grant access token
     *
     * @return
     * OAuth_Response
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
    public function handleTokenRequest(OAuth2_RequestInterface $request)
    {
        $value = $this->getTokenController()->handleTokenRequest($request);
        $this->response = $this->tokenController->getResponse();
        return $value;
    }

    public function grantAccessToken(OAuth2_RequestInterface $request)
    {
        $value = $this->getTokenController()->grantAccessToken($request);
        $this->response = $this->tokenController->getResponse();
        return $value;
    }

    public function getClientCredentials(OAuth2_RequestInterface $request)
    {
        $value = $this->getTokenController()->getClientCredentials($request);
        $this->response = $this->tokenController->getResponse();
        return $value;
    }

    /**
     * Redirect the user appropriately after approval.
     *
     * After the user has approved or denied the resource request the
     * authorization server should call this function to redirect the user
     * appropriately.
     *
     * @param $request
     * The request should have the follow parameters set in the querystring:
     * - response_type: The requested response: an access token, an
     * authorization code, or both.
     * - client_id: The client identifier as described in Section 2.
     * - redirect_uri: An absolute URI to which the authorization server
     * will redirect the user-agent to when the end-user authorization
     * step is completed.
     * - scope: (optional) The scope of the resource request expressed as a
     * list of space-delimited strings.
     * - state: (optional) An opaque value used by the client to maintain
     * state between the request and callback.
     *
     * @param $is_authorized
     * TRUE or FALSE depending on whether the user authorized the access.
     *
     * @param $user_id
     * Identifier of user who authorized the client
     *
     * @see http://tools.ietf.org/html/rfc6749#section-4
     *
     * @ingroup oauth2_section_4
     */
    public function handleAuthorizeRequest(OAuth2_RequestInterface $request, $is_authorized, $user_id = null)
    {
        $value = $this->getAuthorizeController()->handleAuthorizeRequest($request, $is_authorized, $user_id);
        $this->response = $this->authorizeController->getResponse();
        return $value;
    }

    /**
     * Pull the authorization request data out of the HTTP request.
     * - The redirect_uri is OPTIONAL as per draft 20. But your implementation can enforce it
     * by setting $config['enforce_redirect'] to true.
     * - The state is OPTIONAL but recommended to enforce CSRF. Draft 21 states, however, that
     * CSRF protection is MANDATORY. You can enforce this by setting the $config['enforce_state'] to true.
     *
     * The draft specifies that the parameters should be retrieved from GET, override the Response
     * object to change this
     *
     * @return
     * The authorization parameters so the authorization server can prompt
     * the user for approval if valid.
     *
     * @see http://tools.ietf.org/html/rfc6749#section-4.1.1
     * @see http://tools.ietf.org/html/rfc6749#section-10.12
     *
     * @ingroup oauth2_section_3
     */
    public function validateAuthorizeRequest(OAuth2_RequestInterface $request)
    {
        $value = $this->getAuthorizeController()->validateAuthorizeRequest($request);
        $this->response = $this->authorizeController->getResponse();
        return $value;
    }

    public function verifyResourceRequest(OAuth2_RequestInterface $request, $scope = null)
    {
        $value = $this->getResourceController()->verifyResourceRequest($request, $scope);
        $this->response = $this->resourceController->getResponse();
        return $value;
    }

    public function getAccessTokenData(OAuth2_RequestInterface $request, $scope = null)
    {
        $value = $this->getResourceController()->getAccessTokenData($request, $scope);
        $this->response = $this->resourceController->getResponse();
        return $value;
    }

    public function addGrantType(OAuth2_GrantTypeInterface $grantType, $key = null)
    {
        if (is_string($key)) {
            $this->grantTypes[$key] = $grantType;
        } else {
            $this->grantTypes[] = $grantType;
        }

        // persist added grant type down to TokenController
        if (!is_null($this->tokenController)) {
            $this->getTokenController()->addGrantType($grantType);
        }
    }

    public function addStorage($storage, $key = null)
    {
        // if explicitly set to a valid key, do not "magically" set below
        if (isset($this->storageMap[$key])) {
            if (!$storage instanceof $this->storageMap[$key]) {
                throw new InvalidArgumentException(sprintf('storage of type "%s" must implement interface "%s"', $key, $this->storageMap[$key]));
            }
            $this->storages[$key] = $storage;
        } elseif (!is_null($key) && !is_numeric($key)) {
            throw new InvalidArgumentException(sprintf('unknown storage key "%s", must be one of [%s]', $key, implode(', ', array_keys($this->storageMap))));
        } else {
            $set = false;
            // set a storage object to each key for the interface it represents
            // this means if an object represents more than one storage type, it will be referenced by multiple storage keys
            // ex: OAuth2_Storage_Pdo will be set for all the $storageMap keys
            foreach ($this->storageMap as $type => $interface) {
                if ($storage instanceof $interface) {
                    $this->storages[$type] = $storage;
                    $set = true;
                }
            }

            if (!$set) {
                throw new InvalidArgumentException(sprintf('storage of class "%s" must implement one of [%s]', get_class($storage), implode(', ', $this->storageMap)));
            }
        }
    }

    public function addResponseType(OAuth2_ResponseTypeInterface $responseType, $key = null)
    {
        if (isset($this->responseTypeMap[$key])) {
            if (!$responseType instanceof $this->responseTypeMap[$key]) {
                throw new InvalidArgumentException(sprintf('responseType of type "%s" must implement interface "%s"', $key, $this->responseTypeMap[$key]));
            }
            $this->responseTypes[$key] = $responseType;
        } elseif (!is_null($key) && !is_numeric($key)) {
            throw new InvalidArgumentException(sprintf('unknown responseType key "%s", must be one of [%s]', $key, implode(', ', array_keys($this->responseTypeMap))));
        } else {
            $set = false;
            foreach ($this->responseTypeMap as $type => $interface) {
                if ($responseType instanceof $interface) {
                    $this->responseTypes[$type] = $responseType;
                    $set = true;
                }
            }

            if (!$set) {
                throw new InvalidArgumentException(sprintf('Unknown response type %s.  Please implement one of [%s]', get_class($responseType), implode(', ', $this->responseTypeMap)));
            }
        }
    }

    public function setScopeUtil($scopeUtil)
    {
        $this->scopeUtil = $scopeUtil;
    }

    public function getResponse()
    {
        return $this->response;
    }
}
