<?php

/**
 *  @see OAuth2_Controller_AuthorizeControllerInterface
 */
class OAuth2_Controller_AuthorizeController implements OAuth2_Controller_AuthorizeControllerInterface
{
    private $response;
    private $clientStorage;
    private $responseTypes;
    private $config;
    private $scopeUtil;

    public function __construct(OAuth2_Storage_ClientInterface $clientStorage, array $responseTypes = array(), array $config = array(), OAuth2_ScopeInterface $scopeUtil = null)
    {
        $this->clientStorage = $clientStorage;
        $this->responseTypes = $responseTypes;
        $this->config = array_merge(array(
            'allow_implicit' => false,
            'enforce_state' => false,
        ), $config);

        if (is_null($scopeUtil)) {
            $scopeUtil = new OAuth2_Scope();
        }
        $this->scopeUtil = $scopeUtil;
    }

    public function handleAuthorizeRequest(OAuth2_RequestInterface $request, $is_authorized, $user_id = null)
    {
        if (!is_bool($is_authorized)) {
            throw new InvalidArgumentException('Argument "is_authorized" must be a boolean.  This method must know if the user has granted access to the client.');
        }

        // We repeat this, because we need to re-validate. In theory, this could be POSTed
        // by a 3rd-party (because we are not internally enforcing NONCEs, etc)
        if (!$params = $this->validateAuthorizeRequest($request)) {
            return $this->response;
        }

        if ($is_authorized === false) {
            $this->response = new OAuth2_Response_Redirect($params['redirect_uri'], 302, 'access_denied', "The user denied access to your application", $params['state']);
            return $this->response;
        }

        if (!$authResult = $this->responseTypes[$params['response_type']]->getAuthorizeResponse($params, $user_id)) {
            // an error has occurred along the way, return error response
            return $this->response;
        }

        list($redirect_uri, $result) = $authResult;
        $uri = $this->buildUri($redirect_uri, $result);

        // return redirect response
        return $this->response = new OAuth2_Response_Redirect($uri);
    }

    public function validateAuthorizeRequest(OAuth2_RequestInterface $request)
    {
        // Make sure a valid client id was supplied (we can not redirect because we were unable to verify the URI)
        if (!$client_id = $request->query("client_id")) {
            // We don't have a good URI to use
            $this->response = new OAuth2_Response_Error(400, 'invalid_client', "No client id supplied");
            return false;
        }

        // Get client details
        if (!$clientData = $this->clientStorage->getClientDetails($client_id)) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_client', 'The client id supplied is invalid');
            return false;
        }

        $clientData += array('redirect_uri' => null); // this should be set.  We should create ClientData interface
        if ($clientData === false) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_client', "Client id does not exist");
            return false;
        }

        // Make sure a valid redirect_uri was supplied. If specified, it must match the clientData URI.
        // @see http://tools.ietf.org/html/rfc6749#section-3.1.2
        // @see http://tools.ietf.org/html/rfc6749#section-4.1.2.1
        // @see http://tools.ietf.org/html/rfc6749#section-4.2.2.1
        if (!($redirect_uri = $request->query('redirect_uri')) && !($redirect_uri = $clientData['redirect_uri'])) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_uri', 'No redirect URI was supplied or stored');
            return false;
        }

        $parts = parse_url($redirect_uri);

        if (isset($parts['fragment']) && $parts['fragment']) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_uri', 'The redirect URI must not contain a fragment');
            return false;
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
        if (!$scope = $this->scopeUtil->getScopeFromRequest($request)) {
            $scope = $this->scopeUtil->getDefaultScope();
        }

        // type and client_id are required
        if (!$response_type || !in_array($response_type, array(self::RESPONSE_TYPE_AUTHORIZATION_CODE, self::RESPONSE_TYPE_ACCESS_TOKEN))) {
            $this->response = new OAuth2_Response_Redirect($redirect_uri, 302, 'invalid_request', 'Invalid or missing response type', $state);
            return false;
        }
        if ($response_type == self::RESPONSE_TYPE_AUTHORIZATION_CODE) {
            if (!isset($this->responseTypes['code'])) {
                $this->response = new OAuth2_Response_Redirect($redirect_uri, 302, 'unsupported_response_type', 'authorization code grant type not supported', $state);
                return false;
            }
            if ($this->responseTypes['code']->enforceRedirect() && !$redirect_uri) {
                $this->response = new OAuth2_Response_Error(400, 'redirect_uri_mismatch', 'The redirect URI is mandatory and was not supplied.');
                return false;
            }
        }

        if ($response_type == self::RESPONSE_TYPE_ACCESS_TOKEN && !$this->config['allow_implicit']) {
            $this->response = new OAuth2_Response_Redirect($redirect_uri, 302, 'unsupported_response_type', 'implicit grant type not supported', $state);
            return false;
        }

        // Validate that the requested scope is supported
        if (false === $scope) {
            $this->response = new OAuth2_Response_Redirect($redirect_uri, 302, 'invalid_client', 'This application requires you specify a scope parameter', $state);
            return false;
        }

        if (!is_null($scope) && !$this->scopeUtil->checkScope($scope, $this->scopeUtil->getSupportedScopes($client_id))) {
            $this->response = new OAuth2_Response_Redirect($redirect_uri, 302, 'invalid_scope', 'An unsupported scope was requested', $state);
            return false;
        }

        // Validate state parameter exists (if configured to enforce this)
        if ($this->config['enforce_state'] && !$state) {
            $this->response = new OAuth2_Response_Redirect($redirect_uri, 302, 'invalid_request', 'The state parameter is required');
            return false;
        }

        // Return retrieved client details together with input
        return array_merge(array('scope' => $scope, 'state' => null), $clientData, $request->getAllQueryParameters(), array('redirect_uri' => $redirect_uri));
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
     * @param string $inputUri
     * @param string $storedUri
     */
    private function validateRedirectUri($inputUri, $storedUri)
    {
        if (!$inputUri || !$storedUri) {
            return false; // if either one is missing, assume INVALID
        }
        return strcasecmp(substr($inputUri, 0, strlen($storedUri)), $storedUri) === 0;
    }

    public function getResponse()
    {
        return $this->response;
    }
}
