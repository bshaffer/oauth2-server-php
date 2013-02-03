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
     * The audience to validate the token against. This is usually the full URI of the OAuth grant requests endpoint.
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

    /**
     * Validates the request by making share all GET parameters exists.
     * @return TRUE if the request is valid, otherwise FALSE.
     * @see OAuth2_GrantTypeInterface::validateRequest()
     */
    public function validateRequest($request)
    {
        if (!$request->request("assertion")) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'Missing parameters: "assertion" required');

            return false;
        }

        return true;
    }

    /**
     * Gets the data from the decoded JWT.
     * @return Array containing the token data if the JWT can be decoded. Otherwise, NULL is returned.
     * @see OAuth2_GrantTypeInterface::getTokenDataFromRequest()
     */
    public function getTokenDataFromRequest($request)
    {

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

        $this->jwt = $jwt;

        $tokenData = array();

        $tokenData['scope'] = $this->getJWTParameter('scope');
        $tokenData['iss'] = $this->getJWTParameter('iss');
        $tokenData['sub'] = $this->getJWTParameter('sub');
        $tokenData['aud'] = $this->getJWTParameter('aud');
        $tokenData['exp'] = $this->getJWTParameter('exp');
        $tokenData['nbf'] = $this->getJWTParameter('nbf');
        $tokenData['iat'] = $this->getJWTParameter('iat');
        $tokenData['jti'] = $this->getJWTParameter('jti');
        $tokenData['typ'] = $this->getJWTParameter('typ');

        //Other token data in the claim
        foreach ($this->jwt as $key => $value) {
            if (!array_key_exists($key, $tokenData)) {
                $tokenData[$key] = $value;
            }
        }

        return $tokenData;
    }


    /**
     * Helper function to make it easier to return a JWT parameter.
     * @param string $parameter
     * The JWT parameter to get.
     * @param mixed $default
     * The value to return if the JWT parameter does not exist.
     * @return mixed
     * The JWT parameter.
     */
    private function getJWTParameter($parameter, $default = null)
    {
        return isset($this->jwt->$parameter) ? $this->jwt->$parameter : null;
    }

    /**
     * Return the data used to verify the request. For JWT bearer authorization grants, the 'iss' is synonymous to the 'client_id'.
     * The subject is 'sub' and the 'client_secret' is the key to decode the JWT.
     * @return array An array of the client data containing the client_id.
     * @see OAuth2_ClientAssertionTypeInterface::getClientDataFromRequest()
     */
    public function getClientDataFromRequest(OAuth2_RequestInterface $request)
    {
        $tokenData = $this->getTokenDataFromRequest($request);

        if (!$tokenData) {
            return null;
        }

        if (!isset($tokenData['iss'])) {

            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "Invalid issuer (iss) provided");

            return null;
        }

        //Get the iss's public key (http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-06#section-4.1.1)
        $key = $this->storage->getClientKey($tokenData['iss'], $tokenData['sub']);

        if (!$key) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "Invalid issuer (iss) or subject (sub) provided");

            return null;
        }

        return array('client_id' => $tokenData['iss'], 'subject' => $tokenData['sub'], 'client_secret' => $key);
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

            return false;
        }

        foreach ($clientData as $key => $value) {

            if (in_array($key, array('client_id', 'client_secret'))) {

                if (!isset($value)) {
                    throw new LogicException('client_id and client_secret in the clientData array may not be null');

                    return false;
                }
            }
        }

        return true;
    }

    /**
     * Validates the token data using the rules in the IETF draft.
     * @see http://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-04#section-3
     * @see OAuth2_GrantTypeInterface::validateTokenData()
     */
    public function validateTokenData($tokenData, array $clientData)
    {
        // Note: Scope is validated in the client class

        //Check the expiry time
        $expiration = $tokenData['exp'];

        if (ctype_digit($expiration)) {

            if ($expiration <= time()) {
                $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "JWT has expired");

                return false;
            }

        } elseif (!$expiration) {

            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "Expiration (exp) time must be present");

            return false;

        } else {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "Expiration (exp) time must be a unix time stamp");

            return false;
        }


        //Check the not before time
        if ($notBefore = $tokenData['nbf']) {

            if (ctype_digit($notBefore)) {

                if ($notBefore > time()) {
                    $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "JWT cannot be used before the Not Before (nbf) time");

                    return false;
                }

            } else {
                $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "Not Before (nbf) time must be a unix time stamp");

                return false;
            }
        }

        //Check the audience if required to match
        $aud = $tokenData['aud'];
        if (!isset($aud) || ($aud != $this->audience)) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "Invalid audience (aud)");

            return false;
        }

        //Verify the JWT
        $jwt = $this->jwtUtil->decode($this->undecodedJWT, $clientData['client_secret'], true);

        if (!$jwt) {

            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "JWT failed signature verification");
            return null;
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
