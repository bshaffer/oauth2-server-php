<?php

/**
* Service class for OAuth
* Inspired by oauth2-php (https://github.com/quizlet/oauth2-php)
*/
class OAuth2_Server implements OAuth2_Response_ProviderInterface
{
    /**
     * List of possible authentication response types.
     * The "authorization_code" mechanism exclusively supports 'code'
     * and the "implicit" mechanism exclusively supports 'token'.
     *
     * @var string
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.1
     */
    const RESPONSE_TYPE_AUTHORIZATION_CODE = 'code';
    const RESPONSE_TYPE_ACCESS_TOKEN = 'token';

    protected $request;
    protected $response;
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
     * and FALSE if it isn't.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-7
     *
     * @ingroup oauth2_section_7
     */
    public function __construct($storage, array $config = array())
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

        $this->config = array_merge(array(
            'token_type'               => 'bearer',
            'access_lifetime'          => 3600,
            'www_realm'                => 'Service',
            'token_param_name'         => 'access_token',
            'token_bearer_header_name' => 'Bearer',
            'supported_scopes'         => array(),
            'enforce_state'            => false,
            'allow_implicit'           => false,
            'grant_types'              => array(),
        ), $config);

        $this->setGrantTypes($this->config['grant_types']);
    }

    public function handleAccessTokenRequest(OAuth2_Request $request, $grantType = null)
    {
        $this->grantAccessToken($request, $grantType);
        return $this->response;
    }

    /**
     * Grant or deny a requested access token.
     * This would be called from the "/token" endpoint as defined in the spec.
     * Obviously, you can call your endpoint whatever you want.
     *
     * @param $request - OAuth2_Request
     * Request object to grant access token
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
    public function grantAccessToken(OAuth2_Request $request, $grantType = null)
    {
        if (!$grantType instanceof OAuth2_GrantTypeInterface) {
            if (is_null($grantType)) {
                if (!isset($request->query['grant_type']) || !$grantType = $request->query['grant_type']) {
                    $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'The grant type was not specified in the request');
                    return null;
                }
            } else if (!is_string($grantType)) {
                throw new InvalidArgumentException('parameter $grantType must be an instance of OAuth2_GrantTypeInterface, a string representing a configured grant type, or null to pull grant type from request');
            }
            if (!isset($this->grantTypes[$grantType])) {
                /* TODO: If this is an OAuth2 supported grant type that we have chosen not to implement, throw a 501 Not Implemented instead */
                $this->response = new OAuth2_Response_Error(400, 'unsupported_grant_type', sprintf('Grant type "%s" not supported', $grantType));
                return null;
            }
            $grantType = $this->grantTypes[$grantType];
        }

        if (!$clientData = $this->getClientCredentials($request)) {
                return null;
        }

        if (!isset($clientData['client_id']) || !isset($clientData['client_secret'])) {
            throw new LogicException('the clientData array must have "client_id" and "client_secret" values set.  Use getClientCredentials()');
        }

        if ($this->storage['client_credentials']->checkClientCredentials($clientData['client_id'], $clientData['client_secret']) === false) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_client', 'The client credentials are invalid');
            return null;
        }

        if (!$this->storage['client_credentials']->checkRestrictedGrantType($clientData['client_id'], $grantType)) {
            $this->response = new OAuth2_Response_Error(400, 'unauthorized_client', 'The grant type is unauthorized for this client_id');
            return null;
        }

        /* TODO: Find a better way to handle grantTypes and their responses */

        if (!$grantType->validateRequest($request)) {
            if ($grantType instanceof OAuth2_Response_ProviderInterface && $response = $grantType->getResponse()) {
                $this->response = $response;
            } else {
                // create a default response
                $this->response = new OAuth2_Response_Error(400, 'invalid_request', sprintf('Invalid request for "%s" grant type', $grantType->getIdentifier()));
            }
            return null;
        }

        if (!$tokenData = $grantType->getTokenDataFromRequest($request)) {
            if ($grantType instanceof OAuth2_Response_ProviderInterface && $response = $grantType->getResponse()) {
                $this->response = $response;
            } else {
                // create a default response
                $this->response = new OAuth2_Response_Error(400, 'invalid_grant', sprintf('Unable to retrieve token for "%s" grant type', $grantType->getIdentifier()));
            }
            return null;
        }

        if (!$grantType->validateTokenData($tokenData, $clientData)) {
            if ($grantType instanceof OAuth2_Response_ProviderInterface && $response = $grantType->getResponse()) {
                $this->response = $response;
            } else {
                // create a default response
                $this->response = new OAuth2_Response_Error(400, 'invalid_grant', 'Token is no longer valid' );
            }
            return null;
        }

        if (!isset($tokenData["scope"])) {
            $tokenData["scope"] = null;
        }

        // Check scope, if provided
        if (isset($request->query['scope']) && (!is_array($tokenData) || !isset($tokenData["scope"]) || !$this->checkScope($request->query['scope'], $tokenData["scope"]))) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_scope', 'An unsupported scope was requested.');
            return null;
        }

        $user_id = isset($tokenData['user_id']) ? $tokenData['user_id'] : null;
        $token = $this->createAccessToken($clientData['client_id'], $user_id, $tokenData['scope']);

        $grantType->finishTokenGrant($token);

        return $token;
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
     * @param $is_authorized
     * TRUE or FALSE depending on whether the user authorized the access.
     * @param $user_id
     * Identifier of user who authorized the client
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4
     *
     * @ingroup oauth2_section_4
     */
    public function handleAuthorizeRequest(OAuth2_Request $request, $is_authorized, $user_id = null)
    {
        // We repeat this, because we need to re-validate. In theory, this could be POSTed
        // by a 3rd-party (because we are not internally enforcing NONCEs, etc)
        if (!$params = $this->validateAuthorizeParams($request)) {
            return $this->response;
        }

        if ($is_authorized === false) {
            $this->response = new OAuth2_Response_Redirect($params['redirect_uri'], 302, 'access_denied', "The user denied access to your application", $params['state']);
            return $this->response;
        }

        if (!$authResult = $this->grantAuthorizationCode($params, $is_authorized, $user_id)) {
            // an error has occurred along the way, return error response
            return $this->response;
        }

        list($redirect_uri, $result) = $authResult;
        $uri = $this->buildUri($redirect_uri, $result);

        // return redirect response
        return new OAuth2_Response_Redirect($uri);
    }

    // same params as above
    public function grantAuthorizationCode($params, $user_id = null)
    {
        // build the URL to redirect to
        $result = array('query' => array());

        $params += array('scope' => null, 'state' => null);

        if (isset($params['state'])) {
            $result["query"]["state"] = $params['state'];
        }

        if ($params['response_type'] == self::RESPONSE_TYPE_AUTHORIZATION_CODE) {
            $result["query"]["code"] = $this->grantTypes['code']->createAuthorizationCode($params['client_id'], $user_id, $params['redirect_uri'], $params['scope']);
        } elseif ($params['response_type'] == self::RESPONSE_TYPE_ACCESS_TOKEN) {
            $result["fragment"] = $this->createAccessToken($params['client_id'], $user_id, $params['scope']);
        }

        return array($params['redirect_uri'], $result);
    }

    public function verifyAccessTokenRequest(OAuth2_Request $request)
    {
        if ($token = $this->getBearerToken($request)) {
            $scope = isset($request->query['scope']) ? $request->query['scope'] : null;
            return $this->verifyAccessToken($token, $scope);
        }

        return null;
    }

    public function verifyAccessToken($token_param, $scope = null)
    {
        if (!$token_param) { // Access token was not provided
            $this->response = new OAuth2_Response_AuthenticationError(400, 'invalid_request', 'The request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same parameter, uses more than one method for including an access token, or is otherwise malformed.', $this->config['token_type'], $this->config['www_realm'], $scope);
            return null;
        }

        // Get the stored token data (from the implementing subclass)
        $token = $this->storage['access_token']->getAccessToken($token_param);
        if ($token === null) {
            $this->response = new OAuth2_Response_AuthenticationError(401, 'invalid_grant', 'The access token provided is invalid.', $this->config['token_type'], $this->config['www_realm'], $scope);
            return null;
        }

        // Check we have a well formed token
        if (!isset($token["expires"]) || !isset($token["client_id"])) {
            $this->response = new OAuth2_Response_AuthenticationError(401, 'invalid_grant', 'Malformed token (missing "expires" or "client_id")', $this->config['token_type'], $this->config['www_realm'], $scope);
            return null;
        }

        // Check token expiration (expires is a mandatory paramter)
        if (isset($token["expires"]) && time() > strtotime($token["expires"])) {
            $this->response = new OAuth2_Response_AuthenticationError(401, 'invalid_grant', 'The access token provided has expired.', $this->config['token_type'], $this->config['www_realm'], $scope);
            return null;
        }

        // Check scope, if provided
        // If token doesn't have a scope, it's null/empty, or it's insufficient, then throw an error
        if ($scope && (!isset($token["scope"]) || !$token["scope"] || !$this->checkScope($scope, $token["scope"]))) {
            $this->response = new OAuth2_Response_AuthenticationError(401, 'insufficient_scope', 'The request requires higher privileges than provided by the access token.', $this->config['token_type'], $this->config['www_realm'], $scope);
            return null;
        }

        return $token;
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
    public function validateAuthorizeParams(OAuth2_Request $request)
    {
        // Make sure a valid client id was supplied (we can not redirect because we were unable to verify the URI)
        if (!$client_id = $request->query("client_id")) {
            // We don't have a good URI to use
            $this->response = new OAuth2_Response_Error(400, 'invalid_client', "No client id supplied");
            return false;
        }

        // Get client details
        $clientData = $this->storage['client_credentials']->getClientDetails($client_id);
        $clientData += array('redirect_uri' => null); // this should be set.  We should create ClientData interface
        if ($clientData === false) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_client', "Client id does not exist");
            return false;
        }

        // Make sure a valid redirect_uri was supplied. If specified, it must match the clientData URI.
        // @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-3.1.2
        // @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
        // @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
        if (!($redirect_uri = $request->query('redirect_uri')) && !($redirect_uri = $clientData['redirect_uri'])) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_uri', 'No redirect URI was supplied or stored');
            return false;
        }

        $parts = parse_url($redirect_uri);

        if (isset($parts['fragment']) && $parts['fragment']) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_uri', 'The redirect URI must not contain a fragment');
            return false;
        }

        if (isset($this->grantTypes['authorization_code']) && $this->grantTypes['authorization_code']->enforceRedirect() && !$redirect_uri) {
            throw new OAuth2ServerException(self::HTTP_BAD_REQUEST, self::ERROR_REDIRECT_URI_MISMATCH, 'The redirect URI is mandatory and was not supplied.');
        }
        // Only need to validate if redirect_uri provided on input and clientData.
        if ($clientData["redirect_uri"] && $redirect_uri && !$this->validateRedirectUri($redirect_uri, $clientData["redirect_uri"])) {
            $this->response = new OAuth2_Response_Error(400, 'redirect_uri_mismatch', 'The redirect URI provided is missing or does not match');
            return false;
        }

        // Select the redirect URI
        $redirect_uri = $redirect_uri ? $redirect_uri : $clientData["redirect_uri"];
        $response_type = $request->query('response_type');
        $state = $request->query('state');
        $scope = $request->query('scope');

        // type and client_id are required
        if (!$response_type || !in_array($response_type, array(self::RESPONSE_TYPE_AUTHORIZATION_CODE, self::RESPONSE_TYPE_ACCESS_TOKEN))) {
            $this->response = new OAuth2_Response_Redirect($redirect_uri, 302, 'invalid_request', 'Invalid or missing response type', $state);
            return false;
        }

        if ($response_type == self::RESPONSE_TYPE_ACCESS_TOKEN && $this->config['allow_implicit'] === false) {
            $this->response = new OAuth2_Response_Redirect($redirect_uri, 302, 'unsupported_response_type', 'implicit grant type not supported', $state);
            return false;
        }

        // Validate that the requested scope is supported
        if ($scope && !$this->checkScope($scope, $this->config['supported_scopes'])) {
            $this->response = new OAuth2_Response_Redirect($redirect_uri, 302, 'invalid_scope', 'An unsupported scope was requested', $state);
            return false;
        }

        // Validate state parameter exists (if configured to enforce this)
        if ($this->config['enforce_state'] && !$state) {
            $this->response = new OAuth2_Response_Redirect(302, 'invalid_request', 'The state parameter is required');
            return false;
        }

        /* TODO: Add CSRF Protection */

        // Return retrieved client details together with input
        return ($request->query + $clientData + array('state' => null));
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
    protected function createAccessToken($client_id, $user_id, $scope = null)
    {
        $token = array(
            "access_token" => $this->generateAccessToken(),
            "expires_in" => $this->config['access_lifetime'],
            "token_type" => $this->config['token_type'],
            "scope" => $scope
        );

        $this->storage['access_token']->setAccessToken($token["access_token"], $client_id, $user_id, $this->config['access_lifetime'] ? time() + $this->config['access_lifetime'] : null, $scope);

        // Issue a refresh token also, if we support them
        /* TODO: Move this to the grant type */
        if (isset($this->grantTypes['refresh_token'])) {
            $token["refresh_token"] = $this->generateRefreshToken();
            $this->grantTypes['refresh_token']->createRefreshToken($token["refresh_token"], $client_id, $user_id, $scope);
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
     */
    protected function generateAccessToken()
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
     * Generates an unique refresh token
     *
     * Implementing classes may want to override this function to implement
     * other refresh token generation schemes.
     *
     * @return
     * An unique refresh.
     *
     * @ingroup oauth2_section_4
     * @see OAuth2::generateAccessToken()
     */
    protected function generateRefreshToken()
    {
        return $this->generateAccessToken(); // let's reuse the same scheme for token generation
    }

    /**
     * Build the absolute URI based on supplied URI and parameters.
     *
     * @param $uri
     * An absolute URI.
     * @param $params
     * Parameters to be append as GET.
     *
     * @return
     * An absolute URI with supplied parameters.
     *
     * @ingroup oauth2_section_4
     */
    private function buildUri($uri, $params) {
        $parse_url = parse_url($uri);

        // Add our params to the parsed uri
        foreach ( $params as $k => $v ) {
            if (isset($parse_url[$k])) {
                $parse_url[$k] .= "&" . http_build_query($v);
            } else {
                $parse_url[$k] = http_build_query($v);
            }
        }

        // Put humpty dumpty back together
        return
            ((isset($parse_url["scheme"])) ? $parse_url["scheme"] . "://" : "")
            . ((isset($parse_url["user"])) ? $parse_url["user"]
            . ((isset($parse_url["pass"])) ? ":" . $parse_url["pass"] : "") . "@" : "")
            . ((isset($parse_url["host"])) ? $parse_url["host"] : "")
            . ((isset($parse_url["port"])) ? ":" . $parse_url["port"] : "")
            . ((isset($parse_url["path"])) ? $parse_url["path"] : "")
            . ((isset($parse_url["query"])) ? "?" . $parse_url["query"] : "")
            . ((isset($parse_url["fragment"])) ? "#" . $parse_url["fragment"] : "")
        ;
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
    public function getClientCredentials(OAuth2_Request $request)
    {
        if (isset($request->headers['PHP_AUTH_USER'], $request->headers['PHP_AUTH_PW'])) {
            return array('client_id' => $request->headers['PHP_AUTH_USER'], 'client_secret' => $request->headers['PHP_AUTH_PW']);
        }

        // This method is not recommended, but is supported by specification
        if (isset($request->request['client_id'], $request->request['client_secret'])) {
            return array('client_id' => $request->request['client_id'], 'client_secret' => $request->request['client_secret']);
        }

        if (isset($request->query['client_id'], $request->query['client_secret'])) {
            return array('client_id' => $request->query['client_id'], 'client_secret' => $request->query['client_secret']);
        }

        $this->response = new OAuth2_Response_Error(400, 'invalid_client', 'Client credentials were not found in the headers or body');
        return null;
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
            $identifier = $grantType->getIdentifier();
        }

        $this->grantTypes[$identifier] = $grantType;
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
    public function getBearerToken(OAuth2_Request $request)
    {
        if (isset($request->server['AUTHORIZATION'])) {
            $headers = $request->server['AUTHORIZATION'];
        }

        // Check that exactly one method was used
        $methodsUsed = !empty($headers) + isset($request->query[$this->config['token_param_name']]) + isset($request->request[$this->config['token_param_name']]);
        if ($methodsUsed > 1) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'Only one method may be used to authenticate at a time (Auth header, GET or POST).');
            return null;
        }
        if ($methodsUsed == 0) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'The access token was not found.');
            return null;
        }

        // HEADER: Get the access token from the header
        if (!empty($headers)) {
            if (!preg_match('/' . $this->config['token_bearer_header_name'] . '\s(\S+)/', $headers, $matches)) {
                $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'Malformed auth header');
            }
            return $matches[1];
        }

        if (isset($request->request[$this->config['token_param_name']])) {
            // POST: Get the token from POST data
            if ($request->server['REQUEST_METHOD'] != 'POST') {
                $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'When putting the token in the body, the method must be POST.');
                return null;
            }

            if (isset($request->server['CONTENT_TYPE']) && $request->server['CONTENT_TYPE'] != 'application/x-www-form-urlencoded') {
                // IETF specifies content-type. NB: Not all webservers populate this _SERVER variable
                $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'The content type for POST requests must be "application/x-www-form-urlencoded"');
                return null;
            }

            return $request->request[$this->config['token_param_name']];
        }

        // GET method
        return $request->query[$this->config['token_param_name']];
    }

    /**
     * Check if everything in required scope is contained in available scope.
     *
     * @param $required_scope
     * Required scope to be check with.
     *
     * @return
     * TRUE if everything in required scope is contained in available scope,
     * and FALSE if it isn't.
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
     * Internal method for validating redirect URI supplied
     * @param string $inputUri
     * @param string $storedUri
     */
    protected function validateRedirectUri($inputUri, $storedUri) {
        if (!$inputUri || !$storedUri) {
            return false; // if either one is missing, assume INVALID
        }
        return strcasecmp(substr($inputUri, 0, strlen($storedUri)), $storedUri) === 0;
    }
}
