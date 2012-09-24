<?php

/**
* Service class for OAuth
* Inspired by oauth2-php (https://github.com/quizlet/oauth2-php)
*/
class OAuth2_Server
{
    protected $request;
    protected $storage;
    protected $grantTypes;

    /**
     * @param mixed $storage
     * array - array of Objects to implement storage
     * OAuth2_Storage object implementing all required storage types (ClientCredentialsInterface and AccessTokenInterface as a minimum)
     *
     * @param array $grantTypes
     * An array of OAuth2_GrantTypeInterface to use for granting access tokens
     *
     * @param array $config
     * specify a different token lifetime, token header name, etc
     *
     * @param array $response
     * Send in an instance of OAuth2_ResponseInterface to use a different response object
     *
     * @return
     * TRUE if everything in required scope is contained in available scope,
     * and False if it isn't.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-7
     *
     * @ingroup oauth2_section_7
     */
    public function __construct($storage, array $grantTypes = null, array $config = array(), $request = null, OAuth2_ResponseInterface $response = null)
    {
        $validStorage = array(
            'access_token' => 'OAuth2_Storage_AccessTokenInterface',
            'client_credentials' => 'OAuth2_Storage_ClientCredentialsInterface',
            'refresh_token' => 'OAuth2_Storage_RefreshTokenInterface'
        );
        $storage = is_array($storage) ? $storage : array($storage);
        $this->storage = array();
        foreach ($storage as $key => $service) {
            if (isset($validStorage[$key]) && !$service instanceof $validStorage[$key]) {
                throw new InvalidArgumentException(sprintf('storage of type "%s" must implement interface "%s"', $type, $interface));
            }
            foreach ($validStorage as $type => $interface) {
                if ($service instanceof $interface) {
                    $this->storage[$type] = $service;
                }
            }
        }

		if (!isset($this->storage['client_credentials']) || !isset($this->storage['access_token'])) {
			throw new InvalidArgumentException('you must provide at least one storage implementing OAuth2_Server_AccessTokenInterface and one implementing OAuth2_Server_ClientCredentialsInterface');
		}

        if (is_null($request)) {
            $request = OAuth2_Request::createFromGlobals();
        }
        $this->request = $request;

        $this->config = array_merge(array(
            'token_type'               => 'bearer',
            'access_lifetime'          => 3600,
            'refresh_lifetime'         => 1209600,
            'auth_code_lifetime'       => 30,
            'www_realm'                => 'Service',
            'token_param_name'         => 'access_token',
            'token_bearer_header_name' => 'Bearer',
        ), $config);

        $this->setGrantTypes($grantTypes);

        // set response object
        if (is_null($response)) {
            $response = new OAuth2_Response();
        }
        $this->response = $response;
    }

    public function getGrantTypes()
    {
        return $this->grantTypes;
    }

    public function getResponse()
    {
        return $this->response;
    }

    public function setGrantTypes($grantTypes)
    {
        $this->grantTypes = array();
        foreach ($grantTypes as $i => $grantType) {
            $this->addGrantType($grantType, $i);
        }
    }

    public function addGrantType(OAuth2_GrantTypeInterface $grantType, $identifier = null)
    {
        if (is_null($type) || is_numeric($identifier)) {
            $identifier = $grantType->getIdentifier();
        }

        $this->grantTypes[$identifier] = $grantType;
    }

    private function getTypeFromGrantType(OAuth2_GrantTypeInterface $grantType)
    {
        $validGrantTypes = array(
            'password'       => 'OAuth2_Storage_AccessTokenInterface',
            'client_credentials' => 'OAuth2_Storage_ClientCredentialsInterface',
            'refresh_token'      => 'OAuth2_Storage_RefreshTokenInterface'
        );
    }

    /**
     * Grant or deny a requested access token.
     * This would be called from the "/token" endpoint as defined in the spec.
     * Obviously, you can call your endpoint whatever you want.
     *
     * @param $grantType - mixed
     * OAuth2_GrantTypeInterface instance or one of the grant types configured in the constructor
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
    public function grantAccessToken($grantType = null)
    {
        if (!$grantType instanceof OAuth2_GrantTypeInterface) {
            if (is_null($grantType)) {
                if (!isset($this->request->query['grant_type'])) {
                    $this->response->setErrorResponse(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_INVALID_CLIENT, 'The grant type was not specified in the request');
                }
                return null;
            } else if (!is_string($grantType)) {
                throw new InvalidArgumentException('parameter $grantType must be an instance of OAuth2_GrantTypeInterface, a string representing a configured grant type, or null to pull grant type from request');
            }
            if (!isset($this->grantTypes[$grantType])) {
                $this->response->setErrorResponse(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_UNSUPPORTED_GRANT_TYPE, sprintf('Grant type "%s" not supported', $grantType));
                return null;
            }
            $grantType = $this->grantTypes[$grantType];
        }

        if (!$clientData = $this->getClientCredentials()) {
                return null;
        }

        if (!isset($clientData['client_id']) || !isset($clientData['client_secret'])) {
            throw new LogicException('the clientData array must have "client_id" and "client_secret" values set.  Use getClientCredentials()');
        }

        if ($this->storage['client_credentials']->checkClientCredentials($clientData['client_id'], $clientData['client_secret']) === FALSE) {
            $this->response->setErrorResponse(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_INVALID_CLIENT, 'The client credentials are invalid');
            return null;
        }

        if (!$this->storage['client_credentials']->checkRestrictedGrantType($clientData['client_id'], $grantType)) {
            $this->response->setErrorResponse(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_UNAUTHORIZED_CLIENT, 'The grant type is unauthorized for this client_id');
            return null;
        }

        // set response on grant type to utilize error response handling
        $grantType->response = $this->response;

        if (!$grantType->validateRequest($this->request)) {
            return null;
        }

        if (!$tokenData = $grantType->getTokenDataFromRequest($this->request)) {
            return null;
        }

        if (!$grantType->validateTokenData($tokenData)) {
            return null;
        }

        if (!isset($tokenData["scope"])) {
            $tokenData["scope"] = null;
        }

        // Check scope, if provided
        if (isset($this->request->query["scope"]) && (!is_array($tokenData) || !isset($tokenData["scope"]) || !$this->checkScope($this->request->query["scope"], $tokenData["scope"]))) {
            $this->response->setErrorResponse(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_INVALID_SCOPE, 'An unsupported scope was requested.');
            return null;
        }

        $user_id = isset($tokenData['user_id']) ? $tokenData['user_id'] : null;
        $token = $this->createAccessToken($clientData['client_id'], $user_id, $tokenData['scope']);

        return $token;
    }

    public function verifyAccessToken($token_param, $scope = null)
    {
        if (!$token_param) { // Access token was not provided
            $this->response->setErrorResponse(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_INVALID_REQUEST, 'The request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same parameter, uses more than one method for including an access token, or is otherwise malformed.');
            $this->response->setHttpHeaders($this->getAuthorizationErrorHeaders($scope));
            return null;
        }

        // Get the stored token data (from the implementing subclass)
        $token = $this->storage['access_token']->getAccessToken($token_param);
        if ($token === null) {
            $this->response->setErrorResponse(OAuth2_Http::HTTP_UNAUTHORIZED, OAuth2_Http::ERROR_INVALID_GRANT, 'The access token provided is invalid.', $scope);
            $this->response->setHttpHeaders($this->getAuthorizationErrorHeaders($scope));
            return null;
        }

        // Check we have a well formed token
        if (!isset($token["expires"]) || !isset($token["client_id"])) {
            $this->response->setErrorResponse(OAuth2_Http::HTTP_UNAUTHORIZED, OAuth2_Http::ERROR_INVALID_GRANT, 'Malformed token (missing "expires" or "client_id")', $scope);
            $this->response->setHttpHeaders($this->getAuthorizationErrorHeaders($scope));
            return null;
        }

        // Check token expiration (expires is a mandatory paramter)
        if (isset($token["expires"]) && time() > strtotime($token["expires"])) {
            $this->response->setErrorResponse(OAuth2_Http::HTTP_UNAUTHORIZED, OAuth2_Http::ERROR_INVALID_GRANT, 'The access token provided has expired.', $scope);
            $this->response->setHttpHeaders($this->getAuthorizationErrorHeaders($scope));
            return null;
        }

        // Check scope, if provided
        // If token doesn't have a scope, it's NULL/empty, or it's insufficient, then throw an error
        if ($scope && (!isset($token["scope"]) || !$token["scope"] || !$this->checkScope($scope, $token["scope"]))) {
            $this->response->setErrorResponse(OAuth2_Http::HTTP_FORBIDDEN, OAuth2_Http::ERROR_INSUFFICIENT_SCOPE, 'The request requires higher privileges than provided by the access token.', $scope);
            $this->response->setHttpHeaders($this->getAuthorizationErrorHeaders($scope));
            return null;
        }

        return $token;
    }

    /**
     * Handle the creation of access token, also issue refresh token if support.
     *
     * This belongs in a separate factory, but to keep it simple, I'm just
     * keeping it here.
     *
     * @param $client_id
     * Client identifier related to the access token.
     * @param $scope
     * (optional) Scopes to be stored in space-separated string.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5
     * @ingroup oauth2_section_5
     */
    protected function createAccessToken($client_id, $user_id, $scope = NULL)
    {
        $token = array(
            "access_token" => $this->genAccessToken(),
            "expires_in" => $this->config['access_lifetime'],
            "token_type" => $this->config['token_type'],
            "scope" => $scope
        );

        $this->storage['access_token']->setAccessToken($token["access_token"], $client_id, $user_id, $this->config['access_lifetime'] ? time() + $this->config['access_lifetime'] : null, $scope);

        // Issue a refresh token also, if we support them
        if (isset($this->storage['refresh_token'])) {
            $token["refresh_token"] = $this->genAccessToken();
            $this->storage['refresh_token']->setRefreshToken($token["refresh_token"], $client_id, $user_id, time() + $this->config['refresh_lifetime'], $scope);

            // If we've granted a new refresh token, expire the old one
            if ($this->oldRefreshToken) {
                $this->storage['refresh_token']->unsetRefreshToken($this->oldRefreshToken);
                unset($this->oldRefreshToken);
            }
        }

        return $token;
    }

    /**
     * Generates an unique access token.
     *
     * Implementing classes may want to override this function to implement
     * other access token generation schemes.
     *
     * @return
     * An unique access token.
     *
     * @ingroup oauth2_section_4
     * @see OAuth2::genAuthCode()
     */
    protected function genAccessToken()
    {
        $tokenLen = 40;
        if (file_exists('/dev/urandom')) { // Get 100 bytes of random data
            $randomData = file_get_contents('/dev/urandom', false, null, 0, 100) . uniqid(mt_rand(), true);
        } else {
            $randomData = mt_rand() . mt_rand() . mt_rand() . mt_rand() . microtime(true) . uniqid(mt_rand(), true);
        }
        return substr(hash('sha512', $randomData), 0, $tokenLen);
    }

    /**
     * Internal function used to get the client credentials from HTTP basic
     * auth or POST data.
     *
     * According to the spec (draft 20), the client_id can be provided in
     * the Basic Authorization header (recommended) or via GET/POST.
     *
     * @return
     * A list containing the client identifier and password, for example
     * @code
     * return array(
     * CLIENT_ID,
     * CLIENT_SECRET
     * );
     * @endcode
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-2.4.1
     *
     * @ingroup oauth2_section_2
     */
    public function getClientCredentials()
    {
        if (isset($this->request->headers['PHP_AUTH_USER'])) {
            return array('client_id' => $this->request->headers['PHP_AUTH_USER'], 'client_secret' => $this->request->headers['PHP_AUTH_PW']);
        }

        // This method is not recommended, but is supported by specification
        if (isset($this->request->request['client_id'])) {
            return array('client_id' => $this->request->request['client_id'], 'client_secret' => $this->request->request['client_secret']);
        }

        if (isset($this->request->query['client_id'])) {
            return array('client_id' => $this->request->query['client_id'], 'client_secret' => $this->request->query['client_secret']);
        }

        $this->response->setErrorResponse(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_INVALID_CLIENT, 'Client id was not found in the headers or body');
        return null;
    }

    /**
     * Check if everything in required scope is contained in available scope.
     *
     * @param $required_scope
     * Required scope to be check with.
     *
     * @return
     * TRUE if everything in required scope is contained in available scope,
     * and False if it isn't.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-7
     *
     * @ingroup oauth2_section_7
     */
    private function checkScope($required_scope, $available_scope)
    {
        // The required scope should match or be a subset of the available scope
        if (!is_array($required_scope)) {
            $required_scope = explode(' ', trim($required_scope));
        }

        if (!is_array($available_scope)) {
            $available_scope = explode(' ', trim($available_scope));
        }

        return (count(array_diff($required_scope, $available_scope)) == 0);
    }

    /**
     * This is a convenience function that can be used to get the token, which can then
     * be passed to verifyAccessToken(). The constraints specified by the draft are
     * attempted to be adheared to in this method.
     *
     * As per the Bearer spec (draft 8, section 2) - there are three ways for a client
     * to specify the bearer token, in order of preference: Authorization Header,
     * POST and GET.
     *
     * NB: Resource servers MUST accept tokens via the Authorization scheme
     * (http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2).
     *
     * @todo Should we enforce TLS/SSL in this function?
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.2
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.3
     *
     * Old Android version bug (at least with version 2.2)
     * @see http://code.google.com/p/android/issues/detail?id=6684
     *
     * We don't want to test this functionality as it relies on superglobals and headers:
     * @codeCoverageIgnoreStart
     */
    public function getBearerToken()
    {
        if (isset($this->request->server['AUTHORIZATION'])) {
            $headers = $this->request->server['AUTHORIZATION'];
        }

        // Check that exactly one method was used
        $methodsUsed = !empty($headers) + isset($this->request->query[$this->config['token_param_name']]) + isset($this->request->request[$this->config['token_param_name']]);
        if ($methodsUsed > 1) {
            $this->response->setErrorResponse(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_INVALID_REQUEST, 'Only one method may be used to authenticate at a time (Auth header, GET or POST).');
            return null;
        }
        if ($methodsUsed == 0) {
            $this->response->setErrorResponse(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_INVALID_REQUEST, 'The access token was not found.');
            return null;
        }

        // HEADER: Get the access token from the header
        if (!empty($headers)) {
            if (!preg_match('/' . $this->config['token_bearer_header_name'] . '\s(\S+)/', $headers, $matches)) {
                $this->response->setErrorResponse(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_INVALID_REQUEST, 'Malformed auth header');
            }
            return $matches[1];
        }

        if (isset($this->request->request[$this->config['token_param_name']])) {
            // POST: Get the token from POST data
            if ($this->request->server['REQUEST_METHOD'] != 'POST') {
                $this->response->setErrorResponse(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_INVALID_REQUEST, 'When putting the token in the body, the method must be POST.');
                return null;
            }

            if (isset($this->request->server['CONTENT_TYPE']) && $this->request->server['CONTENT_TYPE'] != 'application/x-www-form-urlencoded') {
                // IETF specifies content-type. NB: Not all webservers populate this _SERVER variable
                $this->response->setErrorResponse(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_INVALID_REQUEST, 'The content type for POST requests must be "application/x-www-form-urlencoded"');
                return null;
            }

            return $this->request->request[$this->config['token_param_name']];
        }

        // GET method
        return $this->request->query[$this->config['token_param_name']];
    }

    private function getAuthorizationErrorHeaders($scope = null)
    {
        $header = sprintf('WWW-Authenticate: %s realm=%s', $this->config['token_type'], $this->config['www_realm'], $scope);
        if ($scope) {
            $header = sprintf('%s, scope=%s', $header, $scope);
        }
        return array($header);
    }
}
