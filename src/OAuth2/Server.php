<?php

/**
* Server class for OAuth2
* This class serves as a convience class which wraps the other Controller classes
*
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
    protected $authorizeController;
    protected $tokenController;
    protected $resourceController;

    // config classes
    protected $grantTypes;
    protected $responseTypes;
    protected $tokenType;
    protected $scopeUtil;
    protected $clientAssertionType;

    protected $storageMap = array(
        'access_token' => 'OAuth2_Storage_AccessTokenInterface',
        'authorization_code' => 'OAuth2_Storage_AuthorizationCodeInterface',
        'client_credentials' => 'OAuth2_Storage_ClientCredentialsInterface',
        'client' => 'OAuth2_Storage_ClientInterface',
        'refresh_token' => 'OAuth2_Storage_RefreshTokenInterface',
        'user_credentials' => 'OAuth2_Storage_UserCredentialsInterface',
        'jwt_bearer' => 'OAuth2_Storage_JWTBearerInterface',
        'scope' => 'OAuth2_Storage_ScopeInterface',
    );
    protected $responseTypeMap = array(
        'token' => 'OAuth2_ResponseType_AccessTokenInterface',
        'code' => 'OAuth2_ResponseType_AuthorizationCodeInterface',
    );

    /**
     * @param mixed $storage
     * array - array of Objects to implement storage
     * OAuth2_Storage object implementing all required storage types (ClientCredentialsInterface and AccessTokenInterface as a minimum)
     * @param array $config
     * specify a different token lifetime, token header name, etc
     * @param array $grantTypes
     * An array of OAuth2_GrantTypeInterface to use for granting access tokens
     * @param array $responseTypes
     * Response types to use.  array keys should be "code" and and "token" for
     * Access Token and Authorization Code response types
     * @param OAuth2_TokenTypeInterface $tokenType
     * The token type object to use. Valid token types are "bearer" and "mac"
     * @param OAuth2_ScopeInterface $scopeUtil
     * The scope utility class to use to validate scope
     * @param OAuth2_ClientAssertionTypeInterface $clientAssertionType
     * The method in which to verify the client identity.  Default is HttpBasic
     *
     * @ingroup oauth2_section_7
     */
    public function __construct($storage = array(), array $config = array(), array $grantTypes = array(), array $responseTypes = array(), OAuth2_TokenTypeInterface $tokenType = null, OAuth2_ScopeInterface $scopeUtil = null, OAuth2_ClientAssertionTypeInterface $clientAssertionType = null)
    {
        $storage = is_array($storage) ? $storage : array($storage);
        $this->storages = array();
        foreach ($storage as $key => $service) {
            $this->addStorage($service, $key);
        }

        // merge all config values.  These get passed to our controller objects
        $this->config = array_merge(array(
            'access_lifetime'          => 3600,
            'www_realm'                => 'Service',
            'token_param_name'         => 'access_token',
            'token_bearer_header_name' => 'Bearer',
            'enforce_state'            => true,
            'require_exact_redirect_uri' => true,
            'allow_implicit'           => false,
        ), $config);

        foreach ($grantTypes as $key => $grantType) {
            $this->addGrantType($grantType, $key);
        }
        foreach ($responseTypes as $key => $responseType) {
            $this->addResponseType($responseType, $key);
        }
        $this->tokenType = $tokenType;
        $this->scopeUtil = $scopeUtil;
        $this->clientAssertionType = $clientAssertionType;
    }

    public function getAuthorizeController()
    {
        if (is_null($this->authorizeController)) {
            $this->authorizeController = $this->createDefaultAuthorizeController();
        }
        return $this->authorizeController;
    }

    public function getTokenController()
    {
        if (is_null($this->tokenController)) {
            $this->tokenController = $this->createDefaultTokenController();
        }
        return $this->tokenController;
    }

    public function getResourceController()
    {
        if (is_null($this->resourceController)) {
            $this->resourceController = $this->createDefaultResourceController();
        }
        return $this->resourceController;
    }

    /**
     * every getter deserves a setter
     */
    public function setAuthorizeController(OAuth2_Controller_AuthorizeControllerInterface $authorizeController)
    {
        $this->authorizeController = $authorizeController;
    }

    /**
     * every getter deserves a setter
     */
    public function setTokenController(OAuth2_Controller_TokenControllerInterface $tokenController)
    {
        $this->tokenController = $tokenController;
    }

    /**
     * every getter deserves a setter
     */
    public function setResourceController(OAuth2_Controller_ResourceControllerInterface $resourceController)
    {
        $this->resourceController = $resourceController;
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
    public function handleTokenRequest(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response)
    {
        $this->response = is_null($response) ? new OAuth2_Response() : $response;
        $this->getTokenController()->handleTokenRequest($request, $this->response);
        return $this->response;
    }

    public function grantAccessToken(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response)
    {
        $this->response = is_null($response) ? new OAuth2_Response() : $response;
        $value = $this->getTokenController()->grantAccessToken($request, $this->response);
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
     * @param $is_authorized
     * TRUE or FALSE depending on whether the user authorized the access.
     * @param $user_id
     * Identifier of user who authorized the client
     *
     * @see http://tools.ietf.org/html/rfc6749#section-4
     *
     * @ingroup oauth2_section_4
     */
    public function handleAuthorizeRequest(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response, $is_authorized, $user_id = null)
    {
        $this->response = is_null($response) ? new OAuth2_Response() : $response;
        $this->getAuthorizeController()->handleAuthorizeRequest($request, $this->response, $is_authorized, $user_id);
        return $this->response;
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
    public function validateAuthorizeRequest(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response)
    {
        $this->response = is_null($response) ? new OAuth2_Response() : $response;
        $value = $this->getAuthorizeController()->validateAuthorizeRequest($request, $this->response);
        return $value;
    }

    public function verifyResourceRequest(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response, $scope = null)
    {
        $this->response = is_null($response) ? new OAuth2_Response() : $response;
        $value = $this->getResourceController()->verifyResourceRequest($request, $this->response, $scope);
        return $value;
    }

    public function getAccessTokenData(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response)
    {
        $this->response = is_null($response) ? new OAuth2_Response() : $response;
        $value = $this->getResourceController()->getAccessTokenData($request, $this->response);
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

    /**
     * Set a storage object for the server
     *
     * @param $storage
     * An object implementing one of the Storage interfaces
     * @param $key
     * If null, the storage is set to the key of each storage interface it implements
     *
     * @see storageMap
     */
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

    public function getScopeUtil()
    {
        if (!$this->scopeUtil) {
            $storage = isset($this->storages['scope']) ? $this->storages['scope'] : null;
            $this->scopeUtil = new OAuth2_Scope($storage);
        }
        return $this->scopeUtil;
    }

    /**
     * every getter deserves a setter
     */
    public function setScopeUtil($scopeUtil)
    {
        $this->scopeUtil = $scopeUtil;
    }

    protected function createDefaultAuthorizeController()
    {
        if (!isset($this->storages['client'])) {
                throw new LogicException("You must supply a storage object implementing OAuth2_Storage_ClientInterface to use the authorize server");
        }
        if (0 == count($this->responseTypes)) {
            $this->responseTypes = $this->getDefaultResponseTypes();
        }
        $config = array_intersect_key($this->config, array_flip(explode(' ', 'allow_implicit enforce_state require_exact_redirect_uri')));
        return new OAuth2_Controller_AuthorizeController($this->storages['client'], $this->responseTypes, $config, $this->getScopeUtil());
    }

    protected function createDefaultTokenController()
    {
        if (0 == count($this->grantTypes)) {
            $this->grantTypes = $this->getDefaultGrantTypes();
        }

        if (is_null($this->clientAssertionType)) {
            // see if HttpBasic assertion type is requred.  If so, then create it from storage classes.
            foreach ($this->grantTypes as $grantType) {
                if (!$grantType instanceof OAuth2_ClientAssertionTypeInterface) {
                    if (!isset($this->storages['client_credentials'])) {
                        throw new LogicException("You must supply a storage object implementing OAuth2_Storage_ClientCredentialsInterface to use the token server");
                    }
                    $this->clientAssertionType = new OAuth2_ClientAssertionType_HttpBasic($this->storages['client_credentials']);
                    break;
                }
            }
        }

        return new OAuth2_Controller_TokenController($this->getAccessTokenResponseType(), $this->grantTypes, $this->clientAssertionType, $this->getScopeUtil());
    }

    protected function createDefaultResourceController()
    {
        if (!isset($this->storages['access_token'])) {
            throw new LogicException("You must supply a storage object implementing OAuth2_Storage_AccessTokenInterface to use the resource server");
        }
        if (!$this->tokenType) {
            $this->tokenType = $this->getDefaultTokenType();
        }
        $config = array_intersect_key($this->config, array('www_realm' => ''));
        return new OAuth2_Controller_ResourceController($this->tokenType, $this->storages['access_token'], $config, $this->getScopeUtil());
    }

    protected function getDefaultTokenType()
    {
        $config = array_intersect_key($this->config, array_flip(explode(' ', 'token_param_name token_bearer_header_name')));
        return new OAuth2_TokenType_Bearer($config);
    }

    protected function getDefaultResponseTypes()
    {
        $responseTypes = array();

        if (isset($this->storages['access_token'])) {
            $responseTypes['token'] = $this->getAccessTokenResponseType();
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

        if (count($grantTypes) == 0) {
            throw new LogicException("Unable to build default grant types - You must supply an array of grant_types in the constructor");
        }

        return $grantTypes;
    }

    protected function getAccessTokenResponseType()
    {
        if (isset($this->responseTypes['token'])) {
            return $this->responseTypes['token'];
        }
        if (!isset($this->storages['access_token'])) {
            throw new LogicException("You must supply a response type implementing OAuth2_ResponseType_AccessTokenInterface, or a storage object implementing OAuth2_Storage_AccessTokenInterface to use the token server");
        }
        $refreshStorage = null;
        if (isset($this->storages['refresh_token'])) {
            $refreshStorage = $this->storages['refresh_token'];
        }
        $config = array_intersect_key($this->config, array_flip(explode(' ', 'access_lifetime refresh_token_lifetime')));
        $config['token_type'] = $this->tokenType ? $this->tokenType->getTokenType() :  $this->getDefaultTokenType()->getTokenType();

        return new OAuth2_ResponseType_AccessToken($this->storages['access_token'], $refreshStorage, $config);
    }

    public function getResponse()
    {
        return $this->response;
    }

    public function getStorages()
    {
        return $this->storages;
    }

    public function getStorage($name)
    {
        return isset($this->storages[$name]) ? $this->storages[$name] : null;
    }

    public function getGrantTypes()
    {
        return $this->grantTypes;
    }

    public function getGrantType($name)
    {
        return isset($this->grantTypes[$name]) ? $this->grantTypes[$name] : null;
    }

    public function getResponseTypes()
    {
        return $this->responseTypes;
    }

    public function getResponseType($name)
    {
        return isset($this->responseTypes[$name]) ? $this->responseTypes[$name] : null;
    }

    public function getTokenType()
    {
        return $this->tokenType;
    }

    public function getClientAssertionType()
    {
        return $this->clientAssertionType;
    }

    public function setConfig($name, $value)
    {
        $this->config[$name] = $value;
    }

    public function getConfig($name, $default = null)
    {
        return isset($this->config[$name]) ? $this->config[$name] : $default;
    }
}
