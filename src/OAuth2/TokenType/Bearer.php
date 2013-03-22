<?php

/**
*
*/
class OAuth2_TokenType_Bearer implements OAuth2_TokenTypeInterface, OAuth2_Response_ProviderInterface
{
    private $response;
    private $config;

    public function __construct(array $config = array())
    {
        $this->config = array_merge(array(
            'token_param_name'         => 'access_token',
            'token_bearer_header_name' => 'Bearer',
        ), $config);
    }

    public function getTokenType()
    {
        return 'bearer';
    }

    /**
     * This is a convenience function that can be used to get the token, which can then
     * be passed to getAccessTokenData(). The constraints specified by the draft are
     * attempted to be adheared to in this method.
     *
     * As per the Bearer spec (draft 8, section 2) - there are three ways for a client
     * to specify the bearer token, in order of preference: Authorization Header,
     * POST and GET.
     *
     * NB: Resource servers MUST accept tokens via the Authorization scheme
     * (http://tools.ietf.org/html/rfc6750#section-2).
     *
     * @todo Should we enforce TLS/SSL in this function?
     *
     * @see http://tools.ietf.org/html/rfc6750#section-2.1
     * @see http://tools.ietf.org/html/rfc6750#section-2.2
     * @see http://tools.ietf.org/html/rfc6750#section-2.3
     *
     * Old Android version bug (at least with version 2.2)
     * @see http://code.google.com/p/android/issues/detail?id=6684
     *
     */
    public function getAccessTokenParameter(OAuth2_RequestInterface $request)
    {
        $headers = $request->headers('AUTHORIZATION');

        // Check that exactly one method was used
        $methodsUsed = !empty($headers) + !is_null($request->query($this->config['token_param_name'])) + !is_null($request->request($this->config['token_param_name']));
        if ($methodsUsed > 1) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'Only one method may be used to authenticate at a time (Auth header, GET or POST)');
            return null;
        }
        if ($methodsUsed == 0) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'The access token was not found');
            return null;
        }

        // HEADER: Get the access token from the header
        if (!empty($headers)) {
            if (!preg_match('/' . $this->config['token_bearer_header_name'] . '\s(\S+)/', $headers, $matches)) {
                $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'Malformed auth header');
                return null;
            }
            return $matches[1];
        }

        if ($request->request($this->config['token_param_name'])) {
            // POST: Get the token from POST data
            if (strtolower($request->server('REQUEST_METHOD')) != 'post') {
                $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'When putting the token in the body, the method must be POST');
                return null;
            }

            if ($request->server('CONTENT_TYPE') !== null && $request->server('CONTENT_TYPE') != 'application/x-www-form-urlencoded') {
                // IETF specifies content-type. NB: Not all webservers populate this _SERVER variable
                // @see http://tools.ietf.org/html/rfc6750#section-2.2
                $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'The content type for POST requests must be "application/x-www-form-urlencoded"');
                return null;
            }

            return $request->request($this->config['token_param_name']);
        }

        // GET method
        return $request->query($this->config['token_param_name']);
    }

    public function getResponse()
    {
        return $this->response;
    }
}
