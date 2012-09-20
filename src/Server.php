<?php

/**
* Service class for OAuth
* Inspired by oauth2-php (https://github.com/quizlet/oauth2-php)
*/
class OAuth2_Server
{
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
     * @return
     * TRUE if everything in required scope is contained in available scope,
     * and False if it isn't.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-7
     *
     * @ingroup oauth2_section_7
     */
    public function __construct($storage, array $grantTypes, array $config = array())
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

        $this->setGrantTypes($grantTypes);
        $this->config = array_merge(array(
            'token_type'               => 'bearer',
            'access_lifetime'          => 3600,
            'refresh_lifetime'         => 1209600,
            'auth_code_lifetime'       => 30,
            'www_realm'                => 'Service',
            'token_param_name'         => 'access_token',
            'token_bearer_header_name' => 'Bearer',
        ), $config);
    }

    public function getGrantTypes()
    {
        return $this->grantTypes;
    }

    public function setGrantTypes($grantTypes)
    {
        foreach ($grantTypes as $grantType) {
            if (!$grantType instanceof OAuth2_GrantTypeInterface) {
                throw new InvalidArgumentException('Grant Types are expected to be of type OAuth2_GrantTypeInterface');
            }
        }

        $this->grantTypes = $grantTypes;
    }

    /**
     * Grant or deny a requested access token.
     * This would be called from the "/token" endpoint as defined in the spec.
     * Obviously, you can call your endpoint whatever you want.
     *
     * @param $arguments - The draft specifies that the parameters should be
     * retrieved from POST, but you can override to whatever method you like.
     * @throws OAuth2_Server_Exception
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-21#section-10.6
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-21#section-4.1.3
     *
     * @ingroup oauth2_section_4
     */
    public function grantAccessToken($grantType, array $arguments, array $clientData = null)
    {
        if (!isset($this->grantTypes[$grantType])) {
            throw new OAuth2_Server_Exception(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_UNSUPPORTED_GRANT_TYPE, sprintf('Grant type "%s" not supported', $grantType));
        }

        if (is_null($clientData)) {
            $clientData = $this->getClientCredentials($arguments);
        }

        if (!isset($clientData['client_id']) || !isset($clientData['client_secret'])) {
            throw new InvalidArgumentException('the clientData array must have "client_id" and "client_secret" values set.  Use getClientCredentials()');
        }

        if ($this->storage['client_credentials']->checkClientCredentials($clientData['client_id'], $clientData['client_secret']) === FALSE) {
            throw new OAuth2_Server_Exception(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_INVALID_CLIENT, 'The client credentials are invalid');
        }

        if (!$this->storage['client_credentials']->checkRestrictedGrantType($clientData['client_id'], $grantType)) {
            throw new OAuth2ServerException(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_UNAUTHORIZED_CLIENT, 'The grant type is unauthorized for this client_id');
        }

        if (!$this->grantTypes[$grantType]->validateInputParameters($arguments)) {
            return false;
        }

        if (!$stored = $this->grantTypes[$grantType]->getTokenDataFromInputParameters($arguments)) {
            return false;
        }

        if (!$this->grantTypes[$grantType]->validateTokenData($stored)) {
            return false;
        }

        if (!isset($stored["scope"])) {
            $stored["scope"] = NULL;
        }

        // Check scope, if provided
        if (isset($arguments["scope"]) && (!is_array($stored) || !isset($stored["scope"]) || !$this->checkScope($arguments["scope"], $stored["scope"]))) {
            throw new OAuth2_Server_Exception(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_INVALID_SCOPE, 'An unsupported scope was requested.');
        }

        $user_id = isset($stored['user_id']) ? $stored['user_id'] : null;
        $token = $this->createAccessToken($clientData['client_id'], $user_id, $stored['scope']);

        return $token;
    }

    public function verifyAccessToken($token_param, $scope = null)
    {
        if (!$token_param) { // Access token was not provided
            throw new OAuth2_Authenticate_Exception(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_INVALID_REQUEST, 'The request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same parameter, uses more than one method for including an access token, or is otherwise malformed.', $scope);
        }

        // Get the stored token data (from the implementing subclass)
        $token = $this->storage['access_token']->getAccessToken($token_param);
        if ($token === NULL) {
            throw new OAuth2_Authenticate_Exception(OAuth2_Http::HTTP_UNAUTHORIZED, OAuth2_Http::ERROR_INVALID_GRANT, 'The access token provided is invalid.', $scope);
        }

        // Check we have a well formed token
        if (!isset($token["expires"]) || !isset($token["client_id"])) {
            throw new OAuth2_Authenticate_Exception(OAuth2_Http::HTTP_UNAUTHORIZED, OAuth2_Http::ERROR_INVALID_GRANT, 'Malformed token (missing "expires" or "client_id")', $scope);
        }

        // Check token expiration (expires is a mandatory paramter)
        if (isset($token["expires"]) && time() > strtotime($token["expires"])) {
            throw new OAuth2_Authenticate_Exception(OAuth2_Http::HTTP_UNAUTHORIZED, OAuth2_Http::ERROR_INVALID_GRANT, 'The access token provided has expired.', $scope);
        }

        // Check scope, if provided
        // If token doesn't have a scope, it's NULL/empty, or it's insufficient, then throw an error
        if ($scope && (!isset($token["scope"]) || !$token["scope"] || !$this->checkScope($scope, $token["scope"]))) {
            throw new OAuth2_Authenticate_Exception(OAuth2_Http::HTTP_FORBIDDEN, OAuth2_Http::ERROR_INSUFFICIENT_SCOPE, 'The request requires higher privileges than provided by the access token.', $scope);
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
    public function getClientCredentials(array $inputData, array $authHeaders = null)
    {
        if (is_null($authHeaders)) {
            $authHeaders = $this->getAuthorizationHeader();
        }

        // Basic Authentication is used
        if (!empty($authHeaders['PHP_AUTH_USER'])) {
            return array('client_id' => $authHeaders['PHP_AUTH_USER'], 'client_secret' => $authHeaders['PHP_AUTH_PW']);
        } elseif (empty($inputData['client_id'])) { // No credentials were specified
            throw new OAuth2_Server_Exception(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_INVALID_CLIENT, 'Client id was not found in the headers or body');
        } else {
            // This method is not recommended, but is supported by specification
            return array('client_id' => $inputData['client_id'], 'client_secret' => $inputData['client_secret']);
        }
    }

    protected function getAuthorizationHeader()
    {
        return array(
            'PHP_AUTH_USER' => isset($_SERVER['PHP_AUTH_USER']) ? $_SERVER['PHP_AUTH_USER'] : '',
            'PHP_AUTH_PW' => isset($_SERVER['PHP_AUTH_PW']) ? $_SERVER['PHP_AUTH_PW'] : ''
        );
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
    public function getBearerToken() {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
        } elseif (function_exists('apache_request_headers')) {
            $requestHeaders = apache_request_headers();

            // Server-side fix for bug in old Android versions (a nice side-effect of this fix means we don't care about capitalization for Authorization)
            $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));

            if (isset($requestHeaders['Authorization'])) {
                $headers = trim($requestHeaders['Authorization']);
            }
        }

        // Check that exactly one method was used
        $methodsUsed = !empty($headers) + isset($_GET[$this->config['token_param_name']]) + isset($_POST[$this->config['token_param_name']]);
        if ($methodsUsed > 1) {
            throw new OAuth2_Authenticate_Exception(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_INVALID_REQUEST, 'Only one method may be used to authenticate at a time (Auth header, GET or POST).');
        } elseif ($methodsUsed == 0) {
            throw new OAuth2_Authenticate_Exception(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_INVALID_REQUEST, 'The access token was not found.');
        }

        // HEADER: Get the access token from the header
        if (!empty($headers)) {
            if (!preg_match('/' . $this->config['token_bearer_header_name'] . '\s(\S+)/', $headers, $matches)) {
                throw new OAuth2_Authenticate_Exception(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_INVALID_REQUEST, 'Malformed auth header');
            }

            return $matches[1];
        }

        // POST: Get the token from POST data
        if (isset($_POST[$this->config['token_param_name']])) {
            if ($_SERVER['REQUEST_METHOD'] != 'POST') {
                throw new OAuth2_Authenticate_Exception(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_INVALID_REQUEST, 'When putting the token in the body, the method must be POST.');
            }

            // IETF specifies content-type. NB: Not all webservers populate this _SERVER variable
            if (isset($_SERVER['CONTENT_TYPE']) && $_SERVER['CONTENT_TYPE'] != 'application/x-www-form-urlencoded') {
                throw new OAuth2_Authenticate_Exception(OAuth2_Http::HTTP_BAD_REQUEST, OAuth2_Http::ERROR_INVALID_REQUEST, 'The content type for POST requests must be "application/x-www-form-urlencoded"');
            }

            return $_POST[$this->config['token_param_name']];
        }

        // GET method
        return $_GET[$this->config['token_param_name']];
    }
}
