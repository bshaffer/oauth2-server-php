<?php

namespace OAuth2\GrantType;

use OAuth2\Storage\Bootstrap;
use OAuth2\Server;
use OAuth2\Request\TestRequest;
use OAuth2\Response;
use PHPUnit\Framework\TestCase;

class AuthorizationCodeTest extends TestCase
{
    public function testNoCode()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'client_id' => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
        ));
        $server->handleTokenRequest($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_request');
        $this->assertEquals($response->getParameter('error_description'), 'Missing parameter: "code" is required');
    }

    public function testInvalidCode()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code'          => 'InvalidCode', // invalid authorization code
        ));
        $server->handleTokenRequest($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Authorization code doesn\'t exist or is invalid for the client');
    }

    public function testCodeCannotBeUsedTwice()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code'          => 'testcode', // valid code
        ));
        $server->handleTokenRequest($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 200);
        $this->assertNotNull($response->getParameter('access_token'));

        // try to use the same code again
        $server->handleTokenRequest($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Authorization code doesn\'t exist or is invalid for the client');
    }

    public function testExpiredCode()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code'          => 'testcode-expired', // expired authorization code
        ));
        $server->handleTokenRequest($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'The authorization code has expired');
    }

    public function testValidCode()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code'          => 'testcode', // valid code
        ));
        $token = $server->grantAccessToken($request, new Response());

        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
    }

    public function testValidRedirectUri()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Client ID', // valid client id
            'redirect_uri'  => 'http://brentertainment.com/voil%C3%A0', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code'          => 'testcode-redirect-uri', // valid code
        ));
        $token = $server->grantAccessToken($request, new Response());

        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
    }

    public function testValidCodeNoScope()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code'          => 'testcode-with-scope', // valid code
        ));
        $token = $server->grantAccessToken($request, new Response());

        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
        $this->assertArrayHasKey('scope', $token);
        $this->assertEquals($token['scope'], 'scope1 scope2');
    }

    public function testValidCodeSameScope()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code'          => 'testcode-with-scope', // valid code
            'scope'         => 'scope2 scope1',
        ));
        $token = $server->grantAccessToken($request, new Response());

        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
        $this->assertArrayHasKey('scope', $token);
        $this->assertEquals($token['scope'], 'scope2 scope1');
    }

    public function testValidCodeLessScope()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code'          => 'testcode-with-scope', // valid code
            'scope'         => 'scope1',
        ));
        $token = $server->grantAccessToken($request, new Response());

        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
        $this->assertArrayHasKey('scope', $token);
        $this->assertEquals($token['scope'], 'scope1');
    }

    public function testValidCodeDifferentScope()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code'          => 'testcode-with-scope', // valid code
            'scope'         => 'scope3',
        ));
        $token = $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_scope');
        $this->assertEquals($response->getParameter('error_description'), 'The scope requested is invalid for this request');
    }

    public function testValidCodeInvalidScope()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code'          => 'testcode-with-scope', // valid code
            'scope'         => 'invalid-scope',
        ));
        $token = $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_scope');
        $this->assertEquals($response->getParameter('error_description'), 'The scope requested is invalid for this request');
    }

    public function testValidClientDifferentCode()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Some Other Client', // valid client id
            'client_secret' => 'TestSecret3', // valid client secret
            'code'          => 'testcode', // valid code
        ));
        $token = $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'authorization_code doesn\'t exist or is invalid for the client');
    }

    public function testMissingCodeVerifier()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code'          => 'testcode-pkce-challenge-plain', // valid code
        ));
        $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals('code_verifier_missing', $response->getParameter('error'));
        $this->assertEquals("The PKCE code verifier parameter is required.", $response->getParameter('error_description'));
    }

    public function testInvalidCodeVerifier()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code'          => 'testcode-pkce-challenge-plain', // valid code
            'code_verifier' => 'invalidcodeverifier', // invalid code verifier
        ));
        $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals('code_verifier_invalid', $response->getParameter('error'));
        $this->assertEquals("The PKCE code verifier parameter is invalid.", $response->getParameter('error_description'));
    }

    public function testInvalidPkceChallengeMethod()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code'          => 'testcode-pkce-challenge-invalid-method', // valid code
            'code_verifier' => 'testcodechallengetestcodechallengetestcodechallenge', // valid code verifier
        ));
        $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals('code_challenge_method_invalid', $response->getParameter('error'));
        $this->assertEquals("Unknown PKCE code challenge method.", $response->getParameter('error_description'));
    }

    public function testPkceChallengeMismatch()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code'          => 'testcode-pkce-challenge-plain', // valid code
            'code_verifier' => 'invalidcodeverifierinvalidcodeverifierinvalidcodeverifier', // invalid code verifier
        ));
        $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals('code_verifier_mismatch', $response->getParameter('error'));
        $this->assertEquals("The PKCE code verifier parameter does not match the code challenge.", $response->getParameter('error_description'));
    }

    public function testSuccessfulPlainPkceTokenRequest()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code'          => 'testcode-pkce-challenge-plain', // valid code
            'code_verifier' => 'testcodechallengetestcodechallengetestcodechallenge', // valid code verifier
        ));
        $token = $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 200);
        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
    }

    public function testSuccessfulSha256PkceTokenRequest()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code'          => 'testcode-pkce-challenge-s256', // valid code
            'code_verifier' => 'testcodechallengetestcodechallengetestcodechallenge', // valid code verifier
        ));
        $token = $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 200);
        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
    }

    private function getTestServer($config = [])
    {
        $storage = Bootstrap::getInstance()->getMemoryStorage();
        $server = new Server($storage, $config);
        $server->addGrantType(new AuthorizationCode($storage));

        return $server;
    }
}
