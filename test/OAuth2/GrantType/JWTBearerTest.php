<?php

class OAuth2_GrantType_JWTBearerTest extends PHPUnit_Framework_TestCase
{
    public function testMalformedJWT()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'urn:ietf:params:oauth:grant-type:jwt-bearer'; // valid grant type

        //Get the jwt and break it
        $jwt = $this->getJWT();
        $jwt = substr_replace($jwt, 'broken', 3, 6);

        $request->query['assertion'] = $jwt;

        $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_request');
        $this->assertEquals($response->getParameter('error_description'), 'JWT is malformed');
    }

    public function testBrokenSignature()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'urn:ietf:params:oauth:grant-type:jwt-bearer'; // valid grant type

        //Get the jwt and break signature
        $jwt = $this->getJWT() . 'notSupposeToBeHere';
        $request->query['assertion'] = $jwt;

        $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'JWT failed signature verification');
    }

    public function testExpiredJWT()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'urn:ietf:params:oauth:grant-type:jwt-bearer'; // valid grant type

        //Get an expired JWT
        $jwt = $this->getJWT(1234);
        $request->query['assertion'] = $jwt;

        $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'JWT has expired');
    }

    public function testBadExp()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'urn:ietf:params:oauth:grant-type:jwt-bearer'; // valid grant type

        //Get an expired JWT
        $jwt = $this->getJWT('badtimestamp');
        $request->query['assertion'] = $jwt;

        $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Expiration (exp) time must be a unix time stamp');
    }

    public function testNoAssert()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'urn:ietf:params:oauth:grant-type:jwt-bearer'; // valid grant type

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
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'urn:ietf:params:oauth:grant-type:jwt-bearer'; // valid grant type

        //Get a future NBF
        $jwt = $this->getJWT(null, time() + 10000);
        $request->query['assertion'] = $jwt;

        $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'JWT cannot be used before the Not Before (nbf) time');
    }

    public function testBadNotBefore()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'urn:ietf:params:oauth:grant-type:jwt-bearer'; // valid grant type

        //Get a non timestamp nbf
        $jwt = $this->getJWT(null, 'notatimestamp');
        $request->query['assertion'] = $jwt;

        $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Not Before (nbf) time must be a unix time stamp');
    }

    public function testNonMatchingAudience()
    {
        $server = $this->getTestServer('http://google.com/oauth/o/auth');
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'urn:ietf:params:oauth:grant-type:jwt-bearer'; // valid grant type
        $request->query['assertion'] = $this->getJWT();

        $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Invalid audience (aud)');
    }

    public function testBadClientID()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'urn:ietf:params:oauth:grant-type:jwt-bearer'; // valid grant type
        $request->query['assertion'] = $this->getJWT(null, null, null, 'bad_client_id');

        $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Invalid issuer (iss) or subject (sub) provided');
    }

    public function testBadSbuject()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'urn:ietf:params:oauth:grant-type:jwt-bearer'; // valid grant type
        $request->query['assertion'] = $this->getJWT(null, null, 'anotheruser@ourdomain.com');

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
        $privateKey = "-----BEGIN PRIVATE KEY----- MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCy2DNurVPKjODp af+6DLCeDgnbA85pInA9aUUV9/3YrrStCusIMNRJV66ELT5OOfsurfmAxmuxZrOX eiPgoAcEEVmoE96MRHRn+3XCBmRr3u6ihbYFyXFQyMvqwVb3YEubZ/Y+j9IOMp0Z HC3T6R2PYyCZ2ogO7spM0s9VL/fOTQuf4S233als4OFSWJgeRUXL9lm2hfrqWCAu NlcZ0E/akvH9wBHT0HSbVAMG+TMZ7CYXoeXSBeopIFB6XW+dHw+nZzwWOnewMHrm GJK1eZ9ro2kxkEBvi8Gnf1LJGtteI0fsZtigiIEG2CeFWDjMcAbpu2wTIC2ZUzRo yGfTVModAgMBAAECggEAdqL4q0iLNufxIqVQIEjeuFozq3eA6zkPH42/aG1TlPN/ ovKFKq/JgsWJXODuXdIUj8iUpBn7wniQVcGOHynIvagMw3Q6wu1+EqQ6X3UCFJST 1HfCYWBZrO8mZhnO6NaWEQcL0EBzZTup/sg0lkgjdcSaEbVnYBCDXibRpn7lcZGK MrsHzm6leR9tVbCB7IfT4nPmoWorkJOPcXRmE6kiRYKOKsdvX7p9leMz7ChTL7aF oCSjanO37sx3Vl1Qs8a0hdPO3slXso8/jEyDQEAgOo9SPPF1Eb6ymNIXu83ic/MC LmhFBlb7sjNXP+KCT9dMTSsw6+cYybCh+8Yq6hTgQQKBgQDesyPsWN/pzxT5qHni CngVnoRihK7JDJ2wMAdg853rLFrCn6I4u5jk9U3hDgxdq1N7vOfBtaUnGpeBHM1Q U0oUhukp81I3QyBFgUs1Bjsenu+rQi3zYELKKH/nuTRThKfUQhb5UDwkSKq69Ooc ln2grkOV+UR5nJ3e9aSZvbbXVQKBgQDNlkyso/qm06vzaRu7H6aakhgQb+nMA01z mj5SWimMjd/hv5Mrz3ts1UHqJwT7ElL12pQObDVocLfb5DgX7ttfy36q2OL1+7Pg AxY42lcmXt77olDq+PT4WMzkFbJ2XIeg7aavYIb0EoTxf1rLZNJ+g5gqAb0OCtsp 91NkdygXqQKBgG04kq/Bzt+O7oybMlvIIqkHu4nN5SM5isT0aUoFcTf74u9890S3 zP7NyEpOZ4YxFpqjRU7d1YfeJNvv0kpI7xYuLICkk3gC9frgtI/m5GvaK1Vk+cBZ P6iCQGjXjnA/qUgSuc3Aqh5pfUKAB6nJrQd3MDKHtCuowkytUPMN9nSZAoGAAIu7 nGG7EqJRPI404qRM3vAwXCrP5hjEJeBs9e8DWTovM/w8OcuNOla+nA6KdtgvnDN+ XSNwaNyTwGO0umuJ7ZEuvulggOKwMZIQhwodXR63XNere1Q54kbqFFjyZloMiiLX ZHPPJ+q8q5948D1OScOzrbjfdaAVwODFOekPFDECgYEAnGiC1mwF52JiG6RSwR7M iR1Q2bMJsUW3ofPgOX4diUvg4sihdCj4gmCoKy8Y/rhK9T4Ntti6GPFKqRtjWC7f ja52w2QQbsMYoxeGQoEG4AO92WkJW1Tmj/LufL8C3+Pun+TrSJGreIsMu955v/PF 00cvfSeAGKSc2bXBowyEQQ8= -----END PRIVATE KEY-----";

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

        $jwtUtil = new OAuth2_Util_JWT();

        return $jwtUtil->encode($params, $privateKey);
    }

    private function getTestServer($audience = 'http://myapp.com/oauth/auth')
    {
        $storage = new OAuth2_Storage_Memory(json_decode(file_get_contents(dirname(__FILE__).'/../../config/storage.json'), true));
        $server = new OAuth2_Server($storage);
        $server->addGrantType(new OAuth2_GrantType_JWTBearer($storage, $audience));

        return $server;
    }
}
