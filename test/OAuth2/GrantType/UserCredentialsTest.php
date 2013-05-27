<?php

class OAuth2_GrantType_UserCredentialsTest extends PHPUnit_Framework_TestCase
{
    public function testNoUsername()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'password', // valid grant type
            'client_id' => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'password' => 'testpass', // valid password
        ));
        $server->grantAccessToken($request, $response = new OAuth2_Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_request');
        $this->assertEquals($response->getParameter('error_description'), 'Missing parameters: "username" and "password" required');
    }

    public function testNoPassword()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'password', // valid grant type
            'client_id' => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'username' => 'test-username', // valid username
        ));
        $server->grantAccessToken($request, $response = new OAuth2_Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_request');
        $this->assertEquals($response->getParameter('error_description'), 'Missing parameters: "username" and "password" required');
    }

    public function testInvalidUsername()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'password', // valid grant type
            'client_id' => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'username' => 'fake-username', // valid username
            'password' => 'testpass', // valid password
        ));
        $token = $server->grantAccessToken($request, $response = new OAuth2_Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Invalid username and password combination');
    }

    public function testInvalidPassword()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'password', // valid grant type
            'client_id' => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'username' => 'test-username', // valid username
            'password' => 'fakepass', // invalid password
        ));
        $token = $server->grantAccessToken($request, $response = new OAuth2_Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Invalid username and password combination');
    }

    public function testValidCredentials()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'password', // valid grant type
            'client_id' => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'username' => 'test-username', // valid username
            'password' => 'testpass', // valid password
        ));
        $token = $server->grantAccessToken($request, new OAuth2_Response());

        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
    }

    public function testValidCredentialsWithScope()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'password', // valid grant type
            'client_id' => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'username' => 'test-username', // valid username
            'password' => 'testpass', // valid password
            'scope'    => 'scope1', // valid scope
        ));
        $token = $server->grantAccessToken($request, new OAuth2_Response());

        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
        $this->assertArrayHasKey('scope', $token);
        $this->assertEquals($token['scope'], 'scope1');
    }

    public function testValidCredentialsInvalidScope()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'password', // valid grant type
            'client_id' => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'username' => 'test-username', // valid username
            'password' => 'testpass', // valid password
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
        $server->addGrantType(new OAuth2_GrantType_UserCredentials($storage));

        return $server;
    }
}
