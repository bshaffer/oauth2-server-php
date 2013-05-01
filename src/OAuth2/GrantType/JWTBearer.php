<?php

/**
* The JWT bearer authorization grant implements JWT (JSON Web Tokens) as a grant type per the IETF draft.
* @see http://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-04#section-4
*/
class OAuth2_GrantType_JWTBearer implements OAuth2_GrantTypeInterface, OAuth2_Response_ProviderInterface, OAuth2_ClientAssertionTypeInterface
{
    private $storage;
    private $response;
    private $audience = null;
    private $jwt = null;
    private $undecodedJWT = null;
    private $jwtUtil;

    /**
     * Creates an instance of the JWT bearer grant type.
     *
     * @param OAuth2_Storage_JWTBearerInterface $storage
     * A valid storage interface that implements storage hooks for the JWT bearer grant type.
     * @param string $audience
     * The audience to validate the token against. This is usually the full URI of the OAuth token requests endpoint.
     * @param OAuth2_Encryption_JWT OPTIONAL $jwtUtil
     * The class used to decode, encode and verify JWTs.
     */
    public function __construct(OAuth2_Storage_JWTBearerInterface $storage, $audience,  OAuth2_Encryption_JWT $jwtUtil = null)
    {
        $this->storage = $storage;
        $this->audience = $audience;

        if (is_null($jwtUtil)) {
            $jwtUtil = new OAuth2_Encryption_JWT();
        }

        $this->jwtUtil = $jwtUtil;
    }

    /**
     * Returns the grant_type get parameter to identify the grant type request as JWT bearer authorization grant.
     * @return The string identifier for grant_type.
     * @see OAuth2_GrantTypeInterface::getQuerystringIdentifier()
     */
    public function getQuerystringIdentifier()
    {
        return 'urn:ietf:params:oauth:grant-type:jwt-bearer';
    }

    private function getJWTDataFromRequest($request)
    {
        if (!$this->jwt) {
            if (!$request->request("assertion")) {
                $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'Missing parameters: "assertion" required');
                return null;
            }

            if (!$request->request("assertion")) {
                $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'Missing parameters: "assertion" required');
                return null;
            }

            //Store the undecoded JWT for later use
            $this->undecodedJWT = $request->request('assertion');

            //Decode the JWT
            $jwt = $this->jwtUtil->decode($request->request('assertion'), null, false);

            if (!$jwt) {
                $this->response = new OAuth2_Response_Error(400, 'invalid_request', "JWT is malformed");
                return null;
            }

            // ensure these properties contain a value
            // @todo: throw malformed error for missing properties
            $jwt = array_merge(array(
                'scope' => null,
                'iss' => null,
                'sub' => null,
                'aud' => null,
                'exp' => null,
                'nbf' => null,
                'iat' => null,
                'jti' => null,
                'typ' => null,
            ), $jwt);

            $this->jwt = $jwt;
        }

        return $this->jwt;
    }

    /**
     * Gets the data from the decoded JWT.
     * @return Array containing the token data if the JWT can be decoded. Otherwise, NULL is returned.
     * @see OAuth2_GrantTypeInterface::getTokenData()
     */
    public function getTokenData(OAuth2_RequestInterface $request, array $clientData)
    {
        if (!$jwt = $this->getJWTDataFromRequest($request)) {
            return null;
        }

        //Check the expiry time
        $expiration = $jwt['exp'];

        if (ctype_digit($expiration)) {
            if ($expiration <= time()) {
                $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "JWT has expired");
                return null;
            }
        } elseif (!$expiration) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "Expiration (exp) time must be present");
            return null;
        } else {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "Expiration (exp) time must be a unix time stamp");
            return null;
        }

        //Check the not before time
        if ($notBefore = $jwt['nbf']) {
            if (ctype_digit($notBefore)) {
                if ($notBefore > time()) {
                    $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "JWT cannot be used before the Not Before (nbf) time");
                    return null;
                }
            } else {
                $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "Not Before (nbf) time must be a unix time stamp");
                return null;
            }
        }

        //Check the audience if required to match
        $audience = $jwt['aud'];
        if (!isset($audience) || ($audience != $this->audience)) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "Invalid audience (aud)");
            return null;
        }

        //Verify the JWT
        if (!$this->jwtUtil->decode($this->undecodedJWT, $clientData['client_secret'], true)) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "JWT failed signature verification");
            return null;
        }

        return $jwt;
    }

    /**
     * Return the data used to verify the request. For JWT bearer authorization grants, the 'iss' is synonymous to the 'client_id'.
     * The subject is 'sub' and the 'client_secret' is the key to decode the JWT.
     * @return array An array of the client data containing the client_id.
     * @see OAuth2_ClientAssertionTypeInterface::getClientData()
     */
    public function getClientData(OAuth2_RequestInterface $request)
    {
        if (!$jwt = $this->getJWTDataFromRequest($request)) {
            return null;
        }

        if (!isset($jwt['iss'])) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "Invalid issuer (iss) provided");
            return null;
        }

        //Get the iss's public key (http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-06#section-4.1.1)
        $key = $this->storage->getClientKey($jwt['iss'], $jwt['sub']);

        if (!$key) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "Invalid issuer (iss) or subject (sub) provided");
            return null;
        }

        return array('client_id' => $jwt['iss'], 'subject' => $jwt['sub'], 'client_secret' => $key);
    }

    /**
     * Validates the client data by checking if the client_id exists in storage. It also checks to see if the client_id is associated with a key to decode the JWT.
     * @see OAuth2_ClientAssertionTypeInterface::validateClientData()
     */
    public function validateClientData(array $clientData, $grantTypeIdentifier)
    {
        //Check that all array keys exist
        $diff = array_diff(array_keys($clientData), array('client_id', 'subject', 'client_secret'));

        if (!empty($diff)) {
            throw new DomainException('The clientData array is missing one or more of the following: client_id, subject, client_secret');
        }

        foreach ($clientData as $key => $value) {
            if (in_array($key, array('client_id', 'client_secret'))) {
                if (!isset($value)) {
                    throw new LogicException('client_id and client_secret in the clientData array may not be null');
                }
            }
        }

        return true;
    }

    /**
     * Creates an access token that is NOT associated with a refresh token.
     * If a subject (sub) the name of the user/account we are accessing data on behalf of.
     * @see OAuth2_GrantTypeInterface::createAccessToken()
     */
    public function createAccessToken(OAuth2_ResponseType_AccessTokenInterface $accessToken, array $clientData, array $tokenData)
    {
        $includeRefreshToken = false;
        return $accessToken->createAccessToken($clientData['client_id'], $tokenData['sub'], $tokenData['scope'], $includeRefreshToken);
    }

    /**
     * Returns the response of this grant type.
     * @see OAuth2_Response_ProviderInterface::getResponse()
     */
    public function getResponse()
    {
        return $this->response;
    }
}
