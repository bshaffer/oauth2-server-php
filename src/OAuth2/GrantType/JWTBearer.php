<?php

/**
*
*/
class OAuth2_GrantType_JWTBearer implements OAuth2_GrantTypeInterface, OAuth2_Response_ProviderInterface, OAuth2_ClientAssertionTypeInterface
{
    private $storage;
    private $response;
    private $audience = NULL;
    private $jwt = NULL;
    private $jwtUtil;

    public function __construct(OAuth2_Storage_JWTBearerInterface $storage, $audience,  OAuth2_Util_JWT $jwtUtil = null)
    {
        $this->storage = $storage;
        $this->audience = $audience;
        
        if (is_null($jwtUtil)) {
        	$jwtUtil = new OAuth2_Util_JWT();
        }
        
        $this->jwtUtil = $jwtUtil;
        
    }

    public function getQuerystringIdentifier()
    {
        return 'urn:ietf:params:oauth:grant-type:jwt-bearer';
    }

    public function validateRequest($request)
    {
        if (!$request->query("assertion")) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'Missing parameters: "assertion" required');

            return false;
        }

        return true;
    }

    public function getTokenDataFromRequest($request)
    {

        if (!$request->query("assertion")) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_request', 'Missing parameters: "assertion" required');

            return null;
        }

        //Decode the JWT
        try {
            $jwt = $this->jwtUtil->decode($request->query('assertion'), NULL, FALSE);
        } catch (Exception $e) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_request', "JWT is malformed");

            return null;
        }

        $this->setJWT($jwt);

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

    private function setJWT($jwt)
    {
        $this->jwt = $jwt;
    }

    private function getJWTParameter($parameter, $default = NULL)
    {
        return isset($this->jwt->$parameter) ? $this->jwt->$parameter : NULL;
    }

    public function getClientDataFromRequest(OAuth2_RequestInterface $request)
    {
        $tokenData = $this->getTokenDataFromRequest($request);

        if($tokenData){
            return array('client_id' => $tokenData['iss']);
        }
    }

    public function validateClientData(array $clientData)
    {
        //Get the iss's public key (http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-06#section-4.1.1)
        if (!isset($clientData['client_id'])) {

            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "Invalid issuer (iss) provided");

            return null;
        }

        $publicKey = $this->storage->getClientKey($clientData['client_id']);

        if (!$publicKey) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "Invalid issuer (iss) provided");

            return null;
        }

        return true;
    }

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
        try {
            $this->jwtUtil->decode($this->jwt, $clientData['client_secret'], TRUE);

        } catch (Exception $e) {
            $this->response = new OAuth2_Response_Error(400, 'invalid_grant', "JWT failed signature verification");

            return null;
        }

        return true;
    }

    public function createAccessToken(OAuth2_ResponseType_AccessTokenInterface $accessToken, array $clientData, array $tokenData)
    {
        $includeRefreshToken = false;

        if (isset($tokenData['sub'])) {
            $user = $tokenData['sub'];
        } else {
            $user = $tokenData['iss'];
        }

        return $accessToken->createAccessToken($clientData['client_id'], $user, $tokenData['scope'], $includeRefreshToken);
    }

    public function getResponse()
    {
        return $this->response;
    }
}
