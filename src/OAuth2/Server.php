<?php

/**
* Service class for OAuth
* This class serves only to wrap the other Controller classes
* @see OAuth2_Controller_AccessController
* @see OAuth2_Controller_AuthorizeController
* @see OAuth2_Controller_GrantController
*/
class OAuth2_Server implements OAuth2_Controller_AccessControllerInterface,
    OAuth2_Controller_AuthorizeControllerInterface, OAuth2_Controller_GrantControllerInterface
{
    // misc properties
    protected $response;
    protected $config;
    protected $storages;

    // servers
    protected $accessController;
    protected $authorizeController;
    protected $grantController;

    // config classes
    protected $responseTypes;
    protected $grantTypes;
    protected $accessTokenResponseType;

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
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-7
     *
     * @ingroup oauth2_section_7
     */
    public function __construct($storage = array(), array $config = array(), array $grantTypes = array(), array $responseTypes = array(), OAuth2_ResponseType_AccessTokenInterface $accessTokenResponseType = null)
    {
        $validStorage = array(
            'access_token' => 'OAuth2_Storage_AccessTokenInterface',
            'authorization_code' => 'OAuth2_Storage_AuthorizationCodeInterface',
            'client_credentials' => 'OAuth2_Storage_ClientCredentialsInterface',
            'client' => 'OAuth2_Storage_ClientInterface',
            'refresh_token' => 'OAuth2_Storage_RefreshTokenInterface',
            'user_credentials' => 'OAuth2_Storage_UserCredentialsInterface',
        );
        $storage = is_array($storage) ? $storage : array($storage);
        $this->storages = array();
        foreach ($storage as $key => $service) {
            if (isset($validStorage[$key])) {
                if (!$service instanceof $validStorage[$key]) {
                    throw new InvalidArgumentException(sprintf('storage of type "%s" must implement interface "%s"', $type, $interface));
                }
                $this->storages[$type] = $service;
                continue; // if explicitly set to a valid key, do not "magically" set below
            }
            // set a storage object to each key for the interface it represents
            // this means if an object represents more than one storage type, it will be referenced by multiple storage keys
            // ex: OAuth2_Storage_Pdo will be set for all the $validStorage keys above
            foreach ($validStorage as $type => $interface) {
                if ($service instanceof $interface) {
                    $this->storages[$type] = $service;
                }
            }
        }

        // merge all config values.  These get passed to our controller objects
        $this->config = array_merge(array(
            'token_type'               => 'bearer',
            'access_lifetime'          => 3600,
            'www_realm'                => 'Service',
            'token_param_name'         => 'access_token',
            'token_bearer_header_name' => 'Bearer',
            'supported_scopes'         => array(),
            'enforce_state'            => false,
            'allow_implicit'           => false,
        ), $config);

        $this->responseTypes = $responseTypes;
        $this->grantTypes = $grantTypes;
        $this->accessTokenResponseType = $accessTokenResponseType;
    }

    public function getAccessController()
    {
        if (is_null($this->accessController)) {
            if (is_null($this->config['token_type'])) {
                $this->config['token_type'] = 'bearer';
            }
            $tokenType = null;
            if ($this->config['token_type'] == 'bearer') {
                $config = array_intersect_key($this->config, array_flip(explode(' ', 'token_param_name token_bearer_header_name')));
                $tokenType = new OAuth2_TokenType_Bearer($config);
            } else if ($this->config['token_type'] == 'mac') {
                $tokenType = new OAuth2_TokenType_MAC();
            } else {
                throw new LogicException('unrecognized token type: '.$this->config['token_type']);
            }
            if (!isset($this->storages['access_token'])) {
                throw new LogicException("You must supply a storage object implementing OAuth2_Storage_AccessTokenInterface to use the access server");
            }
            $config = array_intersect_key($this->config, array('www_realm' => ''));
            $this->accessController = new OAuth2_Controller_AccessController($tokenType, $this->storages['access_token'], $config);
        }
        return $this->accessController;
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
            $config = array_intersect_key($this->config, array_flip(explode(' ', 'supported_scopes allow_implicit enforce_state')));
            $this->authorizeController = new OAuth2_Controller_AuthorizeController($this->storages['client'], $this->responseTypes, $config);
        }
        return $this->authorizeController;
    }

    public function getGrantController()
    {
        if (is_null($this->grantController)) {
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
            $this->grantController = new OAuth2_Controller_GrantController($this->storages['client_credentials'], $this->accessTokenResponseType, $this->grantTypes);
        }
        return $this->grantController;
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
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-21#section-10.6
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-21#section-4.1.3
     *
     * @ingroup oauth2_section_4
     */
    public function handleGrantRequest(OAuth2_RequestInterface $request)
    {
        $value = $this->getGrantController()->handleGrantRequest($request);
        $this->response = $this->grantController->getResponse();
        return $value;
    }

    public function grantAccessToken(OAuth2_RequestInterface $request)
    {
        $value = $this->getGrantController()->grantAccessToken($request);
        $this->response = $this->grantController->getResponse();
        return $value;
    }

    public function getClientCredentials(OAuth2_RequestInterface $request)
    {
        $value = $this->getGrantController()->getClientCredentials($request);
        $this->response = $this->grantController->getResponse();
        return $value;
    }

    /**
     * Redirect the user appropriately after approval.
     *
     * After the user has approved or denied the access request the
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
     * - scope: (optional) The scope of the access request expressed as a
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
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4
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
     * by setting CONFIG_ENFORCE_INPUT_REDIRECT to true.
     * - The state is OPTIONAL but recommended to enforce CSRF. Draft 21 states, however, that
     * CSRF protection is MANDATORY. You can enforce this by setting the CONFIG_ENFORCE_STATE to true.
     *
     * The draft specifies that the parameters should be retrieved from GET, override the Response
     * object to change this
     *
     * @return
     * The authorization parameters so the authorization server can prompt
     * the user for approval if valid.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-21#section-10.12
     *
     * @ingroup oauth2_section_3
     */
    public function validateAuthorizeRequest(OAuth2_RequestInterface $request)
    {
        $value = $this->getAuthorizeController()->validateAuthorizeRequest($request);
        $this->response = $this->authorizeController->getResponse();
        return $value;
    }

    public function verifyAccessRequest(OAuth2_RequestInterface $request)
    {
        $value = $this->getAccessController()->verifyAccessRequest($request);
        $this->response = $this->accessController->getResponse();
        return $value;
    }

    public function getAccessTokenData($token_param, $scope = null)
    {
        $value = $this->getAccessController()->getAccessTokenData($token_param, $scope);
        $this->response = $this->accessController->getResponse();
        return $value;
    }

    public function addGrantType(OAuth2_GrantTypeInterface $grantType)
    {
        $this->getGrantController()->addGrantType($grantType);
    }

    public function getResponse()
    {
        return $this->response;
    }
}
