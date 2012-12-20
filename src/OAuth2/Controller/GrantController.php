<?php

class OAuth2_Controller_GrantController implements OAuth2_Controller_GrantControllerInterface
{
    private $response;
    private $clientStorage;
    private $accessToken;
    private $grantTypes;
    private $util;

    public function __construct(OAuth2_Storage_ClientCredentialsInterface $clientStorage, OAuth2_ResponseType_AccessTokenInterface $accessToken, array $grantTypes = array(), $util = null)
    {
        $this->clientStorage = $clientStorage;
        $this->accessToken = $accessToken;
        foreach ($grantTypes as $grantType) {
            $this->addGrantType($grantType);
        }

        if (is_null($util)) {
            $util = new OAuth2_Util();
        }
        $this->util = $util;
    }

    public function handleGrantRequest(OAuth2_RequestInterface $request)
    {
        if ($token = $this->grantAccessToken($request)) {
            $this->response = new OAuth2_Response($token);
        }
        return $this->response;
    }

    /**
     * Grant or deny a requested access token.
     * This would be called from the "/token" endpoint as defined in the spec.
     * You can call your endpoint whatever you want.
     *
     * @param $request - OAuth2_RequestInterface
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
    public function grantAccessToken(OAuth2_RequestInterface $request)
    {
        // Determine grant type from request
        if (!($grantType = $request->query('grant_type')) && !($grantType = $request->request('grant_type'))) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'The grant type was not specified in the request');
            return null;
        }
        if (!isset($this->grantTypes[$grantType])) {
            /* TODO: If this is an OAuth2 supported grant type that we have chosen not to implement, throw a 501 Not Implemented instead */
            $this->response = new OAuth2_Response_Error(400, 'unsupported_grant_type', sprintf('Grant type "%s" not supported', $grantType));
            return null;
        }
        $grantType = $this->grantTypes[$grantType];

        // get and validate client authorization from the request
        if (!$clientData = $this->getClientCredentials($request)) {
            return null;
        }

        if (!isset($clientData['client_id']) || !isset($clientData['client_secret'])) {
            throw new LogicException('the clientData array must have "client_id" and "client_secret" values set.');
        }

        if ($this->clientStorage->checkClientCredentials($clientData['client_id'], $clientData['client_secret']) === false) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_client', 'The client credentials are invalid');
            return null;
        }

        if (!$this->clientStorage->checkRestrictedGrantType($clientData['client_id'], $grantType->getQuerystringIdentifier())) {
            $this->response = new OAuth2_Response_Error(400, 'unauthorized_client', 'The grant type is unauthorized for this client_id');
            return null;
        }

        // validate the request for the token
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
        if (null != $request->query('scope') && (!is_array($tokenData) || !isset($tokenData["scope"]) || !$this->util->checkScope($request->query('scope'), $tokenData["scope"]))) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_scope', 'An unsupported scope was requested.');
            return null;
        }

        $tokenData['user_id'] = isset($tokenData['user_id']) ? $tokenData['user_id'] : null;

        return $grantType->createAccessToken($this->accessToken, $clientData, $tokenData);
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
            $identifier = $grantType->getQuerystringIdentifier();
        }

        $this->grantTypes[$identifier] = $grantType;
    }

    public function getResponse()
    {
        return $this->response;
    }
}