<?php

/**
 * @see OAuth2_Controller_AuthorizeControllerInterface
 */
class OAuth2_Controller_AuthorizeController implements OAuth2_Controller_AuthorizeControllerInterface
{
    private $clientStorage;
    private $responseTypes;
    private $config;
    private $scopeUtil;

    /**
     * @param OAuth2_Storage_ClientInterface $clientStorage
     * REQUIRED Instance of OAuth2_Storage_ClientInterface to retrieve client information
     * @param array $responseTypes
     * OPTIONAL Array of OAuth2_ResponseTypeInterface objects.  Valid array
     * keys are "code" and "token"
     * @param array $config
     * OPTIONAL Configuration options for the server
     * @code
     * $config = array(
     *   'allow_implicit' => false,            // if the controller should allow the "implicit" grant type
     *   'enforce_state'  => true              // if the controller should require the "state" parameter
     *   'require_exact_redirect_uri' => true, // if the controller should require an exact match on the "redirect_uri" parameter
     * );
     * @endcode
     * @param OAuth2_ScopeInterface $scopeUtil
     * OPTIONAL Instance of OAuth2_ScopeInterface to validate the requested scope
     */
    public function __construct(OAuth2_Storage_ClientInterface $clientStorage, array $responseTypes = array(), array $config = array(), OAuth2_ScopeInterface $scopeUtil = null)
    {
        $this->clientStorage = $clientStorage;
        $this->responseTypes = $responseTypes;
        $this->config = array_merge(array(
            'allow_implicit' => false,
            'enforce_state'  => true,
            'require_exact_redirect_uri' => true,
        ), $config);

        if (is_null($scopeUtil)) {
            $scopeUtil = new OAuth2_Scope();
        }
        $this->scopeUtil = $scopeUtil;
    }

    public function handleAuthorizeRequest(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response, $is_authorized, $user_id = null)
    {
        if (!is_bool($is_authorized)) {
            throw new InvalidArgumentException('Argument "is_authorized" must be a boolean.  This method must know if the user has granted access to the client.');
        }

        // We repeat this, because we need to re-validate. In theory, this could be POSTed
        // by a 3rd-party (because we are not internally enforcing NONCEs, etc)
        if (!$params = $this->validateAuthorizeRequest($request, $response)) {
            return;
        }

        if ($is_authorized === false) {
            $response->setRedirect(302, $params['redirect_uri'], $params['state'], 'access_denied', "The user denied access to your application");
            return;
        }

        $authResult = $this->responseTypes[$params['response_type']]->getAuthorizeResponse($params, $user_id);

        list($redirect_uri, $uri_params) = $authResult;
        $uri = $this->buildUri($redirect_uri, $uri_params);

        // return redirect response
        $response->setRedirect(302, $uri);
    }

    public function validateAuthorizeRequest(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response)
    {
        // Make sure a valid client id was supplied (we can not redirect because we were unable to verify the URI)
        if (!$client_id = $request->query("client_id")) {
            // We don't have a good URI to use
            $response->setError(400, 'invalid_client', "No client id supplied");
            return false;
        }

        // Get client details
        if (!$clientData = $this->clientStorage->getClientDetails($client_id)) {
            $response->setError(400, 'invalid_client', 'The client id supplied is invalid');
            return false;
        }

        $registered_redirect_uri = isset($clientData['redirect_uri']) ? $clientData['redirect_uri'] : '';

        // Make sure a valid redirect_uri was supplied. If specified, it must match the clientData URI.
        // @see http://tools.ietf.org/html/rfc6749#section-3.1.2
        // @see http://tools.ietf.org/html/rfc6749#section-4.1.2.1
        // @see http://tools.ietf.org/html/rfc6749#section-4.2.2.1
        if ($redirect_uri = $request->query('redirect_uri')) {
            // validate there is no fragment supplied
            $parts = parse_url($redirect_uri);
            if (isset($parts['fragment']) && $parts['fragment']) {
                $response->setError(400, 'invalid_uri', 'The redirect URI must not contain a fragment');
                return false;
            }

            // validate against the registered redirect uri(s) if available
            if ($registered_redirect_uri && !$this->validateRedirectUri($redirect_uri, $registered_redirect_uri)) {
                $response->setError(400, 'redirect_uri_mismatch', 'The redirect URI provided is missing or does not match', '#section-3.1.2');
                return false;
            }
        } else {
            // use the registered redirect_uri if none has been supplied, if possible
            if (!$registered_redirect_uri) {
                $response->setError(400, 'invalid_uri', 'No redirect URI was supplied or stored');
                return false;
            }

            if (count(explode(' ', $registered_redirect_uri)) > 1) {
                $response->setError(400, 'invalid_uri', 'A redirect URI must be supplied when multiple redirect URIs are registered', '#section-3.1.2.3');
                return false;
            }
            $redirect_uri = $registered_redirect_uri;
        }

        // Select the redirect URI
        $response_type = $request->query('response_type');
        $state = $request->query('state');
        if (!$scope = $this->scopeUtil->getScopeFromRequest($request)) {
            $scope = $this->scopeUtil->getDefaultScope();
        }

        // type and client_id are required
        if (!$response_type || !in_array($response_type, array(self::RESPONSE_TYPE_AUTHORIZATION_CODE, self::RESPONSE_TYPE_ACCESS_TOKEN))) {
            $response->setRedirect(302, $redirect_uri, $state, 'invalid_request', 'Invalid or missing response type', null);
            return false;
        }
        if ($response_type == self::RESPONSE_TYPE_AUTHORIZATION_CODE) {
            if (!isset($this->responseTypes['code'])) {
                $response->setRedirect(302, $redirect_uri, $state, 'unsupported_response_type', 'authorization code grant type not supported', null);
                return false;
            }
            if (!$this->clientStorage->checkRestrictedGrantType($client_id, 'authorization_code')) {
                $response->setRedirect(302, $redirect_uri, $state, 'unauthorized_client', 'The grant type is unauthorized for this client_id', null);
                return false;
            }
            if ($this->responseTypes['code']->enforceRedirect() && !$redirect_uri) {
                $response->setError(400, 'redirect_uri_mismatch', 'The redirect URI is mandatory and was not supplied');
                return false;
            }
        }

        if ($response_type == self::RESPONSE_TYPE_ACCESS_TOKEN) {
            if (!$this->config['allow_implicit']) {
                $response->setRedirect(302, $redirect_uri, $state, 'unsupported_response_type', 'implicit grant type not supported', null);
                return false;
            }
            if (!$this->clientStorage->checkRestrictedGrantType($client_id, 'implicit')) {
                $response->setRedirect(302, $redirect_uri, $state, 'unauthorized_client', 'The grant type is unauthorized for this client_id', null);
                return false;
            }
        }

        // Validate that the requested scope is supported
        if (false === $scope) {
            $response->setRedirect(302, $redirect_uri, $state, 'invalid_client', 'This application requires you specify a scope parameter', null);
            return false;
        }

        if (!is_null($scope) && !$this->scopeUtil->scopeExists($scope, $client_id)) {
            $response->setRedirect(302, $redirect_uri, $state, 'invalid_scope', 'An unsupported scope was requested', null);
            return false;
        }

        // Validate state parameter exists (if configured to enforce this)
        if ($this->config['enforce_state'] && !$state) {
            $response->setRedirect(302, $redirect_uri, null, 'invalid_request', 'The state parameter is required');
            return false;
        }

        // Return retrieved client details together with input
        return array_merge(array('scope' => $scope, 'state' => $state), $clientData, $request->getAllQueryParameters(), array('redirect_uri' => $redirect_uri));
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
    private function buildUri($uri, $params)
    {
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
     * Internal method for validating redirect URI supplied
     *
     * @param string $inputUri
     * The submitted URI to be validated
     * @param string $registeredUriString
     * The allowed URI(s) to validate against.  Can be a space-delimited string of URIs to
     * allow for multiple URIs
     *
     * @see http://tools.ietf.org/html/rfc6749#section-3.1.2
     */
    protected function validateRedirectUri($inputUri, $registeredUriString)
    {
        if (!$inputUri || !$registeredUriString) {
            return false; // if either one is missing, assume INVALID
        }

        $registered_uris = explode(' ', $registeredUriString);
        foreach ($registered_uris as $registered_uri) {
            if ($this->config['require_exact_redirect_uri']) {
                // the input uri is validated against the registered uri using exact match
                if (strcmp($inputUri, $registered_uri) === 0) {
                    return true;
                }
            } else {
                // the input uri is validated against the registered uri using case-insensitive match of the initial string
                // i.e. additional query parameters may be applied
                if (strcasecmp(substr($inputUri, 0, strlen($registered_uri)), $registered_uri) === 0) {
                    return true;
                }
            }
        }
        return false;
    }
}
