<?php

class OAuth2_GrantType_RefreshTokenTest extends PHPUnit_Framework_TestCase
{
    private $storage;

    public function testNoRefreshToken()
    {
        $server = $this->getTestServer();
        $server->addGrantType(new OAuth2_GrantType_RefreshToken($this->storage));

        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'refresh_token',  // valid grant type
            'client_id'  => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret',  // valid client secret
        ));
        $server->grantAccessToken($request, $response = new OAuth2_Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_request');
        $this->assertEquals($response->getParameter('error_description'), 'Missing parameter: "refresh_token" is required');
    }

    public function testInvalidRefreshToken()
    {
        $server = $this->getTestServer();
        $server->addGrantType(new OAuth2_GrantType_RefreshToken($this->storage));

        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'refresh_token', // valid grant type
            'client_id' => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'refresh_token' => 'fake-token', // invalid refresh token
        ));
        $server->grantAccessToken($request, $response = new OAuth2_Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Invalid refresh token');
    }

    public function testValidRefreshTokenWithNewRefreshTokenInResponse()
    {
        $server = $this->getTestServer();
        $server->addGrantType(new OAuth2_GrantType_RefreshToken($this->storage, array('always_issue_new_refresh_token' => true)));

        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'refresh_token', // valid grant type
            'client_id' => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'refresh_token' => 'test-refreshtoken', // valid refresh token
        ));
        $token = $server->grantAccessToken($request, new OAuth2_Response());
        $this->assertTrue(isset($token['refresh_token']), 'refresh token should always refresh');

        $refresh_token = $this->storage->getRefreshToken($token['refresh_token']);
        $this->assertNotNull($refresh_token);
        $this->assertEquals($refresh_token['refresh_token'], $token['refresh_token']);
        $this->assertEquals($refresh_token['client_id'], $request->request('client_id'));
        $this->assertTrue($token['refresh_token'] != 'test-refreshtoken', 'the refresh token returned is not the one used');
        $used_token = $this->storage->getRefreshToken('test-refreshtoken');
        $this->assertNull($used_token, 'the refresh token used is no longer valid');
    }

    public function testValidRefreshTokenWithNoRefreshTokenInResponse()
    {
        $server = $this->getTestServer();
        $server->addGrantType(new OAuth2_GrantType_RefreshToken($this->storage, array('always_issue_new_refresh_token' => false)));

        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'refresh_token', // valid grant type
            'client_id' => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'refresh_token' => 'test-refreshtoken', // valid refresh token
        ));
        $token = $server->grantAccessToken($request, new OAuth2_Response());
        $this->assertFalse(isset($token['refresh_token']), 'refresh token should not be returned');

        $used_token = $this->storage->getRefreshToken('test-refreshtoken');
        $this->assertNotNull($used_token, 'the refresh token used is still valid');
    }

    public function testValidRefreshTokenSameScope()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'refresh_token', // valid grant type
            'client_id' => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'refresh_token' => 'test-refreshtoken-with-scope', // valid refresh token (with scope)
            'scope'         => 'scope2 scope1',
        ));
        $token = $server->grantAccessToken($request, new OAuth2_Response());

        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
        $this->assertArrayHasKey('scope', $token);
        $this->assertEquals($token['scope'], 'scope2 scope1');
    }

    public function testValidRefreshTokenLessScope()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'refresh_token', // valid grant type
            'client_id' => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'refresh_token' => 'test-refreshtoken-with-scope', // valid refresh token (with scope)
            'scope'         => 'scope1',
        ));
        $token = $server->grantAccessToken($request, new OAuth2_Response());

        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
        $this->assertArrayHasKey('scope', $token);
        $this->assertEquals($token['scope'], 'scope1');
    }

    public function testValidRefreshTokenDifferentScope()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'refresh_token', // valid grant type
            'client_id' => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'refresh_token' => 'test-refreshtoken-with-scope', // valid refresh token (with scope)
            'scope'         => 'scope3',
        ));
        $token = $server->grantAccessToken($request, $response = new OAuth2_Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_scope');
        $this->assertEquals($response->getParameter('error_description'), 'An unsupported scope was requested.');
    }

    public function testValidRefreshTokenInvalidScope()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'refresh_token', // valid grant type
            'client_id' => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'refresh_token' => 'test-refreshtoken-with-scope', // valid refresh token (with scope)
            'scope'         => 'invalid-scope',
        ));
        $token = $server->grantAccessToken($request, $response = new OAuth2_Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_scope');
        $this->assertEquals($response->getParameter('error_description'), 'An unsupported scope was requested.');
    }

    private function getTestServer()
    {
        $this->storage = OAuth2_Storage_Bootstrap::getInstance()->getMemoryStorage();
        $server = new OAuth2_Server($this->storage);

        return $server;
    }
}
