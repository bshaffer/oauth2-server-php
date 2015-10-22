<?php

namespace OAuth2\Controller;

use OAuth2\ResponseException;
use OAuth2\ResponseTypeInterface;
use OAuth2\Storage\ClientInterface;
use OAuth2\ScopeInterface;
use OAuth2\Scope;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Zend\Diactoros\Stream;

/**
 * @see OAuth2\Controller\AuthorizeControllerInterface
 */
class AuthorizeController implements AuthorizeControllerInterface
{
    private $scope;
    private $state;
    private $client_id;
    private $redirect_uri;
    private $response_type;

    protected $clientStorage;
    protected $responseTypes;
    protected $config;
    protected $scopeUtil;

    /**
     * @param OAuth2\Storage\ClientInterface $clientStorage REQUIRED Instance of OAuth2\Storage\ClientInterface to retrieve client information
     * @param array                          $responseTypes OPTIONAL Array of OAuth2\ResponseType\ResponseTypeInterface objects.  Valid array
     *                                                      keys are "code" and "token"
     * @param array                          $config        OPTIONAL Configuration options for the server
     *                                                      <code>
     *                                                      $config = array(
     *                                                      'allow_implicit' => false,            // if the controller should allow the "implicit" grant type
     *                                                      'enforce_state'  => true              // if the controller should require the "state" parameter
     *                                                      'require_exact_redirect_uri' => true, // if the controller should require an exact match on the "redirect_uri" parameter
     *                                                      'redirect_status_code' => 302,        // HTTP status code to use for redirect responses @see https://github.com/bshaffer/oauth2-server-php/pull/203
     *                                                      );
     *                                                      </code>
     * @param OAuth2\ScopeInterface          $scopeUtil     OPTIONAL Instance of OAuth2\ScopeInterface to validate the requested scope
     */
    public function __construct(ClientInterface $clientStorage, array $responseTypes = array(), array $config = array(), ScopeInterface $scopeUtil = null)
    {
        $this->clientStorage = $clientStorage;
        $this->responseTypes = $responseTypes;
        $this->config = array_merge(array(
            'allow_implicit' => false,
            'enforce_state'  => true,
            'require_exact_redirect_uri' => true,
            'redirect_status_code' => 302,
        ), $config);

        if (is_null($scopeUtil)) {
            $scopeUtil = new Scope();
        }
        $this->scopeUtil = $scopeUtil;
    }

    public function handleAuthorizeRequest(RequestInterface $request, ResponseInterface $response, $is_authorized, $user_id = null)
    {
        if (!is_bool($is_authorized)) {
            throw new \InvalidArgumentException('Argument "is_authorized" must be a boolean.  This method must know if the user has granted access to the client.');
        }

        $errors = null;

        // We repeat this, because we need to re-validate. The request could be POSTed
        // by a 3rd-party (because we are not internally enforcing NONCEs, etc)
        if (!$this->validateAuthorizeRequest($request, $errors)) {
            $params = array_filter(array(
                'error' => $errors['code'],
                'error_description' => $errors['description'],
                'error_uri' => isset($errors['uri']) ? $errors['uri'] : '',
            ));
            switch ($errors['code']) {
                case 'invalid_client':
                case 'invalid_uri':
                case 'redirect_uri_mismatch':
                    $stream = new Stream('php://temp', 'rw');
                    $stream->write(json_encode($params));
                    return $response
                        ->withStatus(400)
                        ->withHeader('Cache-Control', 'no-store')
                        ->withHeader('Content-Type', 'application/json')
                        ->withBody($stream);
            }

            if ($this->state) {
                $params['state'] = $this->state;
            }

            $url = $this->redirect_uri;
            $parts = parse_url($url);
            $sep = isset($parts['query']) && count($parts['query']) > 0 ? '&' : '?';
            $url .= $sep . http_build_query($params);

            return $response
                ->withStatus($this->config['redirect_status_code'])
                ->withHeader('Location', $url);
        }

        // If no redirect_uri is passed in the request, use client's registered one
        if (empty($this->redirect_uri)) {
            $clientData              = $this->clientStorage->getClientDetails($this->client_id);
            $registered_redirect_uri = $clientData['redirect_uri'];
        }

        // the user declined access to the client's application
        if ($is_authorized === false) {
            $redirect_uri = $this->redirect_uri ?: $registered_redirect_uri;

            return $this->setNotAuthorizedResponse($request, $response, $redirect_uri, $user_id);
        }

        // build the parameters to set in the redirect URI
        $params = $this->buildAuthorizeParameters($request, $response, $user_id);

        $authResult = $this->responseTypes[$this->response_type]->getAuthorizeResponse($params, $user_id);

        list($redirect_uri, $uri_params) = $authResult;

        if (empty($redirect_uri) && !empty($registered_redirect_uri)) {
            $redirect_uri = $registered_redirect_uri;
        }

        $uri = $this->buildUri($redirect_uri, $uri_params);

        // return redirect response
        return $response
            ->withStatus($this->config['redirect_status_code'])
            ->withHeader('Location', $uri);
    }

    protected function setNotAuthorizedResponse(RequestInterface $request, ResponseInterface $response, $redirect_uri, $user_id = null)
    {
        $query = array_filter(array(
            'error' => 'access_denied',
            'error_description' => 'The user denied access to your application',
            'state' => $this->state,
        ));

        // add query to URL redirection
        $redirect_uri = $this->buildUri($redirect_uri, array('query' => $query));

        return $response
            ->withStatus($this->config['redirect_status_code'])
            ->withHeader('Location', $redirect_uri);
    }

    /*
     * We have made this protected so this class can be extended to add/modify
     * these parameters
     */
    protected function buildAuthorizeParameters($request, $response, $user_id)
    {
        // @TODO: we should be explicit with this in the future
        $params = array(
            'scope'         => $this->scope,
            'state'         => $this->state,
            'client_id'     => $this->client_id,
            'redirect_uri'  => $this->redirect_uri,
            'response_type' => $this->response_type,
        );

        return $params;
    }

    public function validateAuthorizeRequest(RequestInterface $request, &$errors = null)
    {
        parse_str($request->getUri()->getQuery(), $query);
        $body = $request->getHeaderLine('content-type') == 'application/json'
            ? json_decode((string) $request->getBody(), true)
            : parse_str((string) $request->getBody());

        $client_id = @$query['client_id'] ?: @$body['client_id'];
        $supplied_redirect_uri = @$query['redirect_uri'] ?: @$body['redirect_uri'];
        $response_type = @$query['response_type'] ?: @$body['response_type'];
        $state = @$query['state'] ?: @$body['state'];

        // Make sure a valid client id was supplied (we can not redirect because we were unable to verify the URI)
        if (empty($client_id)) {
            // We don't have a good URI to use
            $errors = array(
                'code' => 'invalid_client',
                'description' => 'No client id supplied',
            );

            return false;
        }

        // Get client details
        if (!$clientData = $this->clientStorage->getClientDetails($client_id)) {
            $errors = array(
                'code' => 'invalid_client',
                'description' => 'The client id supplied is invalid',
            );

            return false;
        }

        $registered_redirect_uri = isset($clientData['redirect_uri']) ? $clientData['redirect_uri'] : '';

        // Make sure a valid redirect_uri was supplied. If specified, it must match the clientData URI.
        // @see http://tools.ietf.org/html/rfc6749#section-3.1.2
        // @see http://tools.ietf.org/html/rfc6749#section-4.1.2.1
        // @see http://tools.ietf.org/html/rfc6749#section-4.2.2.1
        if (empty($supplied_redirect_uri)) {
            // use the registered redirect_uri if none has been supplied, if possible
            if (!$registered_redirect_uri) {
                $errors = array(
                    'code' => 'invalid_uri',
                    'description' => 'No redirect URI was supplied or stored',
                );

                return false;
            }

            if (count(explode(' ', $registered_redirect_uri)) > 1) {
                $errors = array(
                    'code' => 'invalid_uri',
                    'description' => 'A redirect URI must be supplied when multiple redirect URIs are registered',
                    'uri' => '#section-3.1.2.3'
                );

                return false;
            }

            $redirect_uri = $registered_redirect_uri;
        } else {
            // validate there is no fragment supplied
            $parts = parse_url($supplied_redirect_uri);
            if (isset($parts['fragment']) && $parts['fragment']) {
                $errors = array(
                    'code' => 'invalid_uri',
                    'description' => 'The redirect URI must not contain a fragment',
                );

                return false;
            }

            // validate against the registered redirect uri(s) if available
            if ($registered_redirect_uri && !$this->validateRedirectUri($supplied_redirect_uri, $registered_redirect_uri)) {
                $errors = array(
                    'code' => 'redirect_uri_mismatch',
                    'description' => 'The redirect URI provided is missing or does not match',
                    'uri' => '#section-3.1.2'
                );

                return false;
            }

            $redirect_uri = $supplied_redirect_uri;
        }

        // for multiple-valued response types - make them alphabetical
        if (false !== strpos($response_type, ' ')) {
            $types = explode(' ', $response_type);
            sort($types);
            $response_type = ltrim(implode(' ', $types));
        }

        // type and client_id are required
        if (!$response_type || !in_array($response_type, $this->getValidResponseTypes())) {
            $errors = array(
                'code' => 'invalid_request',
                'description' => 'Invalid or missing response type',
            );

            return false;
        }

        // set these in case we throw an error
        // redirect_uri may be set to something else if the verification succeeds
        $this->redirect_uri  = $redirect_uri;
        $this->state         = $state;

        if ($response_type == self::RESPONSE_TYPE_AUTHORIZATION_CODE) {
            if (!isset($this->responseTypes['code'])) {
                $errors = array(
                    'code' => 'unsupported_response_type',
                    'description' => 'authorization code grant type not supported',
                );

                return false;
            }
            if (!$this->clientStorage->checkRestrictedGrantType($client_id, 'authorization_code')) {
                $errors = array(
                    'code' => 'unauthorized_client',
                    'description' => 'The grant type is unauthorized for this client_id',
                );

                return false;
            }

            if ($this->responseTypes['code']->enforceRedirect() && empty($redirect_uri)) {
                $errors = array(
                    'code' => 'redirect_uri_mismatch',
                    'description' => 'The redirect URI is mandatory and was not supplied',
                );

                return false;
            }
        } else {
            if (!$this->config['allow_implicit']) {
                $errors = array(
                    'code' => 'unsupported_response_type',
                    'description' => 'implicit grant type not supported',
                );

                return false;
            }
            if (!$this->clientStorage->checkRestrictedGrantType($client_id, 'implicit')) {
                $errors = array(
                    'code' => 'unauthorized_client',
                    'description' => 'The grant type is unauthorized for this client_id',
                );

                return false;
            }
        }

        // validate requested scope if it exists
        $requestedScope = $this->scopeUtil->getScopeFromRequest($request);

        if ($requestedScope) {
            // restrict scope by client specific scope if applicable,
            // otherwise verify the scope exists
            $clientScope = $this->clientStorage->getClientScope($client_id);
            if ((is_null($clientScope) && !$this->scopeUtil->scopeExists($requestedScope))
                || ($clientScope && !$this->scopeUtil->checkScope($requestedScope, $clientScope))) {
                $errors = array(
                    'code' => 'invalid_scope',
                    'description' => 'An unsupported scope was requested',
                );

                return false;
            }
        } else {
            // use a globally-defined default scope
            $defaultScope = $this->scopeUtil->getDefaultScope($client_id);

            if (false === $defaultScope) {
                $errors = array(
                    'code' => 'invalid_request',
                    'description' => 'This application requires you specify a scope parameter',
                );

                return false;
            }

            $requestedScope = $defaultScope;
        }

        // Validate state parameter exists (if configured to enforce this)
        if ($this->config['enforce_state'] && !$state) {
            $errors = array(
                'code' => 'invalid_request',
                'description' => 'The state parameter is required',
            );

            return false;
        }

        // save the input data and return true
        $this->scope         = $requestedScope;
        $this->client_id     = $client_id;
        // Only save the SUPPLIED redirect URI
        // @see http://tools.ietf.org/html/rfc6749#section-4.1.3
        $this->redirect_uri  = $supplied_redirect_uri;
        $this->response_type = $response_type;

        return true;
    }

    /**
     * Build the absolute URI based on supplied URI and parameters.
     *
     * @param $uri    An absolute URI.
     * @param $params Parameters to be append as GET.
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
        foreach ($params as $k => $v) {
            if (isset($parse_url[$k])) {
                $parse_url[$k] .= "&" . http_build_query($v, '', '&');
            } else {
                $parse_url[$k] = http_build_query($v, '', '&');
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
            . ((isset($parse_url["query"]) && !empty($parse_url['query'])) ? "?" . $parse_url["query"] : "")
            . ((isset($parse_url["fragment"])) ? "#" . $parse_url["fragment"] : "")
        ;
    }

    protected function getValidResponseTypes()
    {
        return array(
            self::RESPONSE_TYPE_ACCESS_TOKEN,
            self::RESPONSE_TYPE_AUTHORIZATION_CODE,
        );
    }

    /**
     * Internal method for validating redirect URI supplied
     *
     * @param string $inputUri            The submitted URI to be validated
     * @param string $registeredUriString The allowed URI(s) to validate against.  Can be a space-delimited string of URIs to
     *                                    allow for multiple URIs
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

    /**
     * Convenience methods to access the parameters derived from the validated request
     */

    public function getScope()
    {
        return $this->scope;
    }

    public function getState()
    {
        return $this->state;
    }

    public function getClientId()
    {
        return $this->client_id;
    }

    public function getRedirectUri()
    {
        return $this->redirect_uri;
    }

    public function getResponseType()
    {
        return $this->response_type;
    }
}
