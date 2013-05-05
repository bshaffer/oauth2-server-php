<?php

class OAuth2_GrantType_AuthorizationCodeTest extends PHPUnit_Framework_TestCase
{
    public function testNoCode()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'client_id' => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
        ));
        $server->handleTokenRequest($request, $response = new OAuth2_Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_request');
        $this->assertEquals($response->getParameter('error_description'), 'Missing parameter: "code" is required');
    }

    public function testInvalidCode()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code'          => 'InvalidCode', // invalid authorization code
        ));
        $server->handleTokenRequest($request, $response = new OAuth2_Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Authorization code doesn\'t exist or is invalid for the client');
    }

    public function testCodeCannotBeUsedTwice()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code'          => 'testcode', // valid code
        ));
        $server->handleTokenRequest($request, $response = new OAuth2_Response());

        $this->assertEquals($response->getStatusCode(), 200);
        $this->assertNotNull($response->getParameter('access_token'));

        // try to use the same code again
        $server->handleTokenRequest($request, $response = new OAuth2_Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Authorization code doesn\'t exist or is invalid for the client');
    }

    public function testValidCode()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code'          => 'testcode', // valid code
        ));
        $token = $server->grantAccessToken($request, new OAuth2_Response());

        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
    }

    public function testValidCodeNoScope()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code'          => 'testcode-with-scope', // valid code
        ));
        $token = $server->grantAccessToken($request, new OAuth2_Response());

        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
        $this->assertArrayHasKey('scope', $token);
        $this->assertEquals($token['scope'], 'scope1 scope2');
    }

    public function testValidCodeSameScope()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code'          => 'testcode-with-scope', // valid code
            'scope'         => 'scope2 scope1',
        ));
        $token = $server->grantAccessToken($request, new OAuth2_Response());

        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
        $this->assertArrayHasKey('scope', $token);
        $this->assertEquals($token['scope'], 'scope2 scope1');
    }

    public function testValidCodeLessScope()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code'          => 'testcode-with-scope', // valid code
            'scope'         => 'scope1',
        ));
        $token = $server->grantAccessToken($request, new OAuth2_Response());

        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
        $this->assertArrayHasKey('scope', $token);
        $this->assertEquals($token['scope'], 'scope1');
    }

    public function testValidCodeDifferentScope()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code'          => 'testcode-with-scope', // valid code
            'scope'         => 'scope3',
        ));
        $token = $server->grantAccessToken($request, $response = new OAuth2_Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_scope');
        $this->assertEquals($response->getParameter('error_description'), 'An unsupported scope was requested.');
    }

    public function testValidCodeInvalidScope()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type'    => 'authorization_code', // valid grant type
            'client_id'     => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code'          => 'testcode-with-scope', // valid code
            'scope'         => 'invalid-scope',
        ));
        $token = $server->grantAccessToken($request, $response = new OAuth2_Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_scope');
        $this->assertEquals($response->getParameter('error_description'), 'An unsupported scope was requested.');
    }

    private function getTestServer()
    {
        $storage = OAuth2_Storage_Bootstrap::getInstance()->getMemoryStorage();
        $server = new OAuth2_Server($storage);
        $server->addGrantType(new OAuth2_GrantType_AuthorizationCode($storage));

        return $server;
    }
}
