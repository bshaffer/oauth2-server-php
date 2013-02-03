<?php

/**
*
*/
class OAuth2_ClientAssertionType_HttpBasic implements OAuth2_ClientAssertionTypeInterface, OAuth2_Response_ProviderInterface
{
    private $response;
    private $storage;

    public function __construct(OAuth2_Storage_ClientCredentialsInterface $storage)
    {
        $this->storage = $storage;
    }

    public function getClientDataFromRequest(OAuth2_RequestInterface $request)
    {
            if (!$clientData = $this->getClientCredentials($request)) {
                return null;
            }

            if (!isset($clientData['client_id']) || !isset($clientData['client_secret'])) {
                throw new LogicException('the clientData array must have "client_id" and "client_secret" values set.');
            }

            return $clientData;
    }

    public function validateClientData(array $clientData, $grantTypeIdentifier)
    {
        if ($this->storage->checkClientCredentials($clientData['client_id'], $clientData['client_secret']) === false) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_client', 'The client credentials are invalid');
            return false;
        }

        if (!$this->storage->checkRestrictedGrantType($clientData['client_id'], $grantTypeIdentifier)) {
            $this->response = new OAuth2_Response_Error(400, 'unauthorized_client', 'The grant type is unauthorized for this client_id');
            return false;
        }

        return true;
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
     * @see http://tools.ietf.org/html/rfc6749#section-2.4.1
     *
     * @ingroup oauth2_section_2
     */
    public function getClientCredentials(OAuth2_RequestInterface $request)
    {
        if (!is_null($request->headers('PHP_AUTH_USER')) && !is_null($request->headers('PHP_AUTH_PW'))) {
            return array('client_id' => $request->headers('PHP_AUTH_USER'), 'client_secret' => $request->headers('PHP_AUTH_PW'));
        }

        // This method is not recommended, but is supported by specification
        if (!is_null($request->request('client_id')) && !is_null($request->request('client_secret'))) {
            return array('client_id' => $request->request('client_id'), 'client_secret' => $request->request('client_secret'));
        }

        if (!is_null($request->query('client_id')) && !is_null($request->query('client_secret'))) {
            return array('client_id' => $request->query('client_id'), 'client_secret' => $request->query('client_secret'));
        }

        $this->response = new OAuth2_Response_Error(400, 'invalid_client', 'Client credentials were not found in the headers or body');
        return null;
    }

    public function getResponse()
    {
        return $this->response;
    }
}