<?php

class OAuth2_GrantType_JWTBearerTest extends PHPUnit_Framework_TestCase
{
    public function testMalformedJWT()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer', // valid grant type
        ));

        //Get the jwt and break it
        $jwt = $this->getJWT();
        $jwt = substr_replace($jwt, 'broken', 3, 6);

        $request->request['assertion'] = $jwt;

        $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_request');
        $this->assertEquals($response->getParameter('error_description'), 'JWT is malformed');
    }

    public function testBrokenSignature()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer', // valid grant type
        ));

        //Get the jwt and break signature
        $jwt = $this->getJWT() . 'notSupposeToBeHere';
        $request->request['assertion'] = $jwt;

        $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'JWT failed signature verification');
    }

    public function testExpiredJWT()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer', // valid grant type
        ));

        //Get an expired JWT
        $jwt = $this->getJWT(1234);
        $request->request['assertion'] = $jwt;

        $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'JWT has expired');
    }

    public function testBadExp()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer', // valid grant type
        ));

        //Get an expired JWT
        $jwt = $this->getJWT('badtimestamp');
        $request->request['assertion'] = $jwt;

        $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Expiration (exp) time must be a unix time stamp');
    }

    public function testNoAssert()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer', // valid grant type
        ));

        //Do not pass the assert (JWT)

        $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_request');
        $this->assertEquals($response->getParameter('error_description'), 'Missing parameters: "assertion" required');
    }

    public function testNotBefore()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer', // valid grant type
        ));

        //Get a future NBF
        $jwt = $this->getJWT(null, time() + 10000);
        $request->request['assertion'] = $jwt;

        $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'JWT cannot be used before the Not Before (nbf) time');
    }

    public function testBadNotBefore()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer', // valid grant type
        ));

        //Get a non timestamp nbf
        $jwt = $this->getJWT(null, 'notatimestamp');
        $request->request['assertion'] = $jwt;

        $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Not Before (nbf) time must be a unix time stamp');
    }

    public function testNonMatchingAudience()
    {
        $server = $this->getTestServer('http://google.com/oauth/o/auth');
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer', // valid grant type
            'assertion' => $this->getJWT(),
        ));

        $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Invalid audience (aud)');
    }

    public function testBadClientID()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',  // valid grant type
            'assertion' => $this->getJWT(null, null, null, 'bad_client_id'),
        ));

        $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Invalid issuer (iss) or subject (sub) provided');
    }

    public function testBadSubject()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',  // valid grant type
            'assertion' => $this->getJWT(null, null, 'anotheruser@ourdomain,com'),
        ));

        $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Invalid issuer (iss) or subject (sub) provided');
    }

    public function testMissingKey()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',  // valid grant type
            'assertion' => $this->getJWT(null, null, null, 'Missing Key Cli,nt'),
        ));

        $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Invalid issuer (iss) or subject (sub) provided');
    }

    /**
     * Generates a JWT
     * @param $exp The expiration date. If the current time is greater than the exp, the JWT is invalid.
     * @param $nbf The "not before" time. If the current time is less than the nbf, the JWT is invalid.
     * @param $sub The subject we are acting on behalf of. This could be the email address of the user in the system.
     * @param $iss The issuer, usually the client_id.
     * @return string
     */
    private function getJWT($exp = null, $nbf = null, $sub = null, $iss = 'Test Client ID')
    {
        $privateKey = <<<EOD
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC/yMgbkPnOnrXt
rcbxZVtTUXdYedy28V6Td04F2h6Meh+XAQrpifoxTTF5c3QgcHq9+3ZcQH/tBnSA
NY+aXa37mo0e325I0v9cR40g/fbZLV0qp+4vVboWYfSlppiDYritM6JAaLEjzmQ0
OXGgI7gXGUZwHSXNa0DGfHnKo0hJ2PoEcJYLxVDLHcMcZ4rJ9yh3y3hCQQnAfN4U
dhQg8SJlWr2ziwofyDFOeuai7M0jburTAx7z93JmWn//Q14pLr4855csGKLq5gv8
dajXopD++2ez6X1Y0W3g9owdwWyFmsHv7BUcD09zBmRDVRm+jD9PPlZc6j1k9sBN
6rA9VhdTAgMBAAECggEARJi7QmjjgQzxg5bhjpwzQyTjbCkCUgkZS+Oja6JtxM81
l1xPG+M3MwUqSgeKpMO2k1drKWoEl7H0X5tIxuz0+wZ3rXA7UR7vKYGKMB/GeD2q
kkRIhHPEQJc+2zUwXeYkqgbK5QDNQ0JiQu+8/YtpIBHxSM6UI9pV6+i/40Pt6kNr
/v1nGqu2KfwVEJ7O5moFdyLaR6QHFc9hxUxeAdcC6QOEoAp59+8UBkXFe5sK6VNO
iRBgnAIrppopkDG2XTb2zA1dZFYnUmgeLtL9lDIBv2KOxUCI5KZe5wTaRQzLRVrG
2DFvE4HrBIl3hAoy/wDhVPkw/mEfk9Y+8lKhdYC5gQKBgQDexfU1z03yV4DA5sxB
8ZLEiJBkfPPNwhgY85/Thb4Xd4bDq7mPIkqWtIXSrWBKC9+uF3cN3Aq65rU/hZ8k
n9CqZdkYfGyBburwhTfd/9n/LNXjDDsrmvBqBf2yxOReLKNU+Xp8/Opov/bMrwS5
BBMCVSnkXqke6GJuUEd+fHI6wQKBgQDcY5ZWxFCn2u8+VTw7rA2465cxDjfVBWOP
99lI+vzSjeoxqsfnD27yxiVlMlct09X2oF2Z8NRr1Ekb+SFzPoANfqj1B6Knsp0w
3FivvCABCVPEXtLIdlfibsewtgTs3Kx2IvzS1XL1gN+awHiIut47deAAuZIZWqvm
skESO+F7EwKBgELOzxjSEKgqwbwX+w2TqtYxtkvMhTkhiiSBe17t7vIOsGWh7EYW
nJPRk4h44jWSlgQZmWSYpsciRRzFr9JF80gGvzJurgOrBd4XtYdoITI7efFbS6tq
Dctd/JVOIsZzUJA9ORSerJW5bAQ6QIpTxHegnq2UDdftDQfUH3y5SXCBAoGAI+9h
DhjIhfYe2G0RezFcs3BGoMsOs39DcrAZD9tM6hAVxa9xFO3hS1iftFZ2/JPz6VjQ
qk8oc8STfyoqGB5yxsCGUB3Emc937gWfuFfWaBTbQcOsXt9dCSDDEr87IlwBCuo9
iyseqYUv8I29mZ3OqqdXtQaNGfE84kribVSyOV0CgYAbsee2ZZ1ufzSC5olW9nQh
5dGELbq4DhlpJg8etWc6GIn87ITOjx4xDSDh75YS8PHDZVjctCWUhgtBzvcYVlpQ
xZwD+bNYZXcbzzExGIh+YIkfpvY5rqCNRgN84YRYB585949H+rYIXB04Pou5UVuK
Fnh+zeEVijg18pMvVScrBw==
-----END PRIVATE KEY-----
EOD;

        //Since PHP 5.2 does not have OpenSSL support on Travis CI, we will test it using the HS256 algorithm
        //We also provided PHP 5.2 specific data for it in storage.json
        $newPHP = true;

        if (version_compare(PHP_VERSION, '5.3.3') <= 0) {
            $iss .= ' PHP-5.2';
            $newPHP = false;
            $privateKey = 'mysecretkey';
        }

        if (!$exp) {
            $exp = time() + 1000;
        }

        if(!$sub){
            $sub = "testuser@ourdomain.com";
        }

        $params = array(
                    'iss' => $iss,
                    'exp' => $exp,
                    'iat' => time(),
                    'sub' => $sub,
                    'aud' => 'http://myapp.com/oauth/auth',
                    'scope' => 'view_friends_list'
                );

        if ($nbf) {
            $params['nbf'] = $nbf;
        }

        $jwtUtil = new OAuth2_Encryption_JWT();

        if ($newPHP){
            return $jwtUtil->encode($params, $privateKey, 'RS256');
        }else{
            return $jwtUtil->encode($params, $privateKey, 'HS256');
        }

    }

    private function getTestServer($audience = 'http://myapp.com/oauth/auth')
    {
        $storage = new OAuth2_Storage_Memory(json_decode(file_get_contents(dirname(__FILE__).'/../../config/storage.json'), true));
        $server = new OAuth2_Server($storage);
        $server->addGrantType(new OAuth2_GrantType_JWTBearer($storage, $audience));

        return $server;
    }
}
