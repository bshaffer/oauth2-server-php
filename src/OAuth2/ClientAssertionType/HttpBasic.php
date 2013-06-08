<?php

/**
 * Validate a client via Http Basic authentication
 *
 * @author    Brent Shaffer <bshafs at gmail dot com>
 */
class OAuth2_ClientAssertionType_HttpBasic implements OAuth2_ClientAssertionTypeInterface
{
    private $storage;
    private $config;
    private $clientData;

    public function __construct(OAuth2_Storage_ClientCredentialsInterface $storage, array $config = array())
    {
        $this->storage = $storage;
        $this->config = array_merge(array(
            'allow_credentials_in_request_body' => true
        ), $config);
    }

    public function validateRequest(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response)
    {
        if (!$clientData = $this->getClientCredentials($request, $response)) {
            return false;
        }

        if (!isset($clientData['client_id']) || !isset($clientData['client_secret'])) {
            throw new LogicException('the clientData array must have "client_id" and "client_secret" values set.');
        }

        if ($this->storage->checkClientCredentials($clientData['client_id'], $clientData['client_secret']) === false) {
            $response->setError(400, 'invalid_client', 'The client credentials are invalid');
            return false;
        }

        if (!$this->storage->checkRestrictedGrantType($clientData['client_id'], $request->request('grant_type'))) {
            $response->setError(400, 'unauthorized_client', 'The grant type is unauthorized for this client_id');
            return false;
        }

        $this->clientData = $clientData;

        return true;
    }

    public function getClientId()
    {
        return $this->clientData['client_id'];
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
     *     "client_id"     => CLIENT_ID,        // REQUIRED the client id
     *     "client_secret" => CLIENT_SECRET,    // REQUIRED the client secret
     * );
     * @endcode
     *
     * @see http://tools.ietf.org/html/rfc6749#section-2.3.1
     *
     * @ingroup oauth2_section_2
     */
    public function getClientCredentials(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response = null)
    {
        if (!is_null($request->headers('PHP_AUTH_USER')) && !is_null($request->headers('PHP_AUTH_PW'))) {
            return array('client_id' => $request->headers('PHP_AUTH_USER'), 'client_secret' => $request->headers('PHP_AUTH_PW'));
        }

        if ($this->config['allow_credentials_in_request_body']) {
            // Using POST for HttpBasic authorization is not recommended, but is supported by specification
            if (!is_null($request->request('client_id'))) {
                /**
                 * client_secret can be null if the client's password is an empty string
                 * @see http://tools.ietf.org/html/rfc6749#section-2.3.1
                 */
                return array('client_id' => $request->request('client_id'), 'client_secret' => $request->request('client_secret', ''));
            }
        }

        if ($response) {
            $response->setError(400, 'invalid_client', 'Client credentials were not found in the headers or body');
        }

        return null;
    }
}