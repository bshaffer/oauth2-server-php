<?php

namespace OAuth2\Controller;

use OAuth2\Storage\Bootstrap;
use OAuth2\Server;
use OAuth2\GrantType\AuthorizationCode;
use OAuth2\GrantType\ClientCredentials;
use OAuth2\GrantType\UserCredentials;
use OAuth2\Scope;
use OAuth2\Request\TestRequest;
use Zend\Diactoros\Response;

class TokenControllerTest extends \PHPUnit_Framework_TestCase
{
    public function testNoGrantType()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $response = $server->handleTokenRequest(TestRequest::createPost());
        $params = json_decode((string) $response->getBody(), true);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($params['error'], 'invalid_request');
        $this->assertEquals($params['error_description'], 'The grant type was not specified in the request');
    }

    public function testInvalidGrantType()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'invalid_grant_type', // invalid grant type
        ));
        $response = $server->handleTokenRequest($request);
        $params = json_decode((string) $response->getBody(), true);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($params['error'], 'unsupported_grant_type');
        $this->assertEquals($params['error_description'], 'Grant type "invalid_grant_type" not supported');
    }

    public function testNoClientId()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'code'       => 'testcode',
        ));
        $response = $server->handleTokenRequest($request);
        $params = json_decode((string) $response->getBody(), true);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($params['error'], 'invalid_client');
        $this->assertEquals($params['error_description'], 'Client credentials were not found in the headers or body');
    }

    public function testNoClientSecretWithConfidentialClient()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'code'       => 'testcode',
            'client_id' => 'Test Client ID', // valid client id
        ));
        $server->handleTokenRequest($request);
        $params = json_decode((string) $response->getBody(), true);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($params['error'], 'invalid_client');
        $this->assertEquals($params['error_description'], 'This client is invalid or must authenticate using a client secret');
    }

    public function testNoClientSecretWithEmptySecret()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'code'       => 'testcode-empty-secret',
            'client_id' => 'Test Client ID Empty Secret', // valid client id
        ));
        $server->handleTokenRequest($request);
        $params = json_decode((string) $response->getBody(), true);

        $this->assertEquals($response->getStatusCode(), 200);
    }

    public function testInvalidClientId()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'code'       => 'testcode',
            'client_id'  => 'Fake Client ID', // invalid client id
            'client_secret' => 'TestSecret', // valid client secret
        ));
        $server->handleTokenRequest($request);
        $params = json_decode((string) $response->getBody(), true);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($params['error'], 'invalid_client');
        $this->assertEquals($params['error_description'], 'The client credentials are invalid');
    }

    public function testInvalidClientSecret()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'code'       => 'testcode',
            'client_id'  => 'Test Client ID', // valid client id
            'client_secret' => 'Fake Client Secret', // invalid client secret
        ));
        $server->handleTokenRequest($request);
        $params = json_decode((string) $response->getBody(), true);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($params['error'], 'invalid_client');
        $this->assertEquals($params['error_description'], 'The client credentials are invalid');
    }

    public function testValidTokenResponse()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'client_id' => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code' => 'testcode', // valid authorization code
        ));
        $response = $server->handleTokenRequest($request);
        $params = json_decode((string) $response->getBody(), true);

        $this->assertTrue($response instanceof Response);
        $this->assertEquals($response->getStatusCode(), 200);
        $this->assertNull($params['error']);
        $this->assertNull($params['error_description']);
        $this->assertNotNull($params['access_token']);
        $this->assertNotNull($params['expires_in']);
        $this->assertNotNull($params['token_type']);
    }

    public function testValidClientIdScope()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'code'       => 'testcode',
            'client_id' => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'scope' => 'clientscope1 clientscope2'
        ));
        $response = $server->handleTokenRequest($request);
        $params = json_decode((string) $response->getBody(), true);

        $this->assertEquals($response->getStatusCode(), 200);
        $this->assertNull($params['error']);
        $this->assertNull($params['error_description']);
        $this->assertEquals('clientscope1 clientscope2', $params['scope']);
    }

    public function testInvalidClientIdScope()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'code'       => 'testcode-with-scope',
            'client_id' => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'scope' => 'clientscope3'
        ));
        $response = $server->handleTokenRequest($request);
        $params = json_decode((string) $response->getBody(), true);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($params['error'], 'invalid_scope');
        $this->assertEquals($params['error_description'], 'The scope requested is invalid for this request');
    }

    public function testEnforceScope()
    {
        $storage = Bootstrap::getInstance()->getMemoryStorage();
        $server = new Server($storage);
        $server->addGrantType(new ClientCredentials($storage));

        $scope = new Scope(array(
            'default_scope' => false,
            'supported_scopes' => array('testscope')
        ));
        $server->setScopeUtil($scope);

        $request = TestRequest::createPost(array(
            'grant_type' => 'client_credentials', // valid grant type
            'client_id'  => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
        ));
        $response = $server->handleTokenRequest($request);
        $params = json_decode((string) $response->getBody(), true);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($params['error'], 'invalid_scope');
        $this->assertEquals($params['error_description'], 'This application requires you specify a scope parameter');
    }

    public function testCanReceiveAccessTokenUsingPasswordGrantTypeWithoutClientSecret()
    {
        // add the test parameters in memory
        $storage = Bootstrap::getInstance()->getMemoryStorage();
        $server = new Server($storage);
        $server->addGrantType(new UserCredentials($storage));

        $request = TestRequest::createPost(array(
            'grant_type' => 'password',                          // valid grant type
            'client_id'  => 'Test Client ID For Password Grant', // valid client id
            'username'   => 'johndoe',                           // valid username
            'password'   => 'password',                          // valid password for username
        ));
        $response = $server->handleTokenRequest($request);
        $params = json_decode((string) $response->getBody(), true);

        $this->assertTrue($response instanceof Response);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertNull($params['error']);
        $this->assertNull($params['error_description']);
        $this->assertNotNull($params['access_token']);
        $this->assertNotNull($params['expires_in']);
        $this->assertNotNull($params['token_type']);
    }

    public function testInvalidTokenTypeHintForRevoke()
    {
        $server = $this->getTestServer();

        $request = TestRequest::createPost(array(
            'token_type_hint' => 'foo',
            'token' => 'sometoken'
        ));

        $response = $server->handleRevokeRequest($request);
        $params = json_decode((string) $response->getBody(), true);

        $this->assertTrue($response instanceof Response);
        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals($params['error'], 'invalid_request');
        $this->assertEquals($params['error_description'], 'Token type hint must be either \'access_token\' or \'refresh_token\'');
    }

    public function testMissingTokenForRevoke()
    {
        $server = $this->getTestServer();

        $request = TestRequest::createPost(array(
            'token_type_hint' => 'access_token'
        ));

        $response = $server->handleRevokeRequest($request);
        $params = json_decode((string) $response->getBody(), true);
        $this->assertTrue($response instanceof Response);
        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals($params['error'], 'invalid_request');
        $this->assertEquals($params['error_description'], 'Missing token parameter to revoke');
    }

    public function testInvalidRequestMethodForRevoke()
    {
        $server = $this->getTestServer();

        $request = new TestRequest(array(
            'token_type_hint' => 'access_token'
        ));

        $response = $server->handleRevokeRequest($request);
        $params = json_decode((string) $response->getBody(), true);
        $this->assertTrue($response instanceof Response);
        $this->assertEquals(405, $response->getStatusCode(), var_export($response, 1));
        $this->assertEquals($params['error'], 'invalid_request');
        $this->assertEquals($params['error_description'], 'The request method must be POST when revoking an access token');
    }

    public function testCreateController()
    {
        $storage = Bootstrap::getInstance()->getMemoryStorage();
        $accessToken = new \OAuth2\ResponseType\AccessToken($storage);
        $controller = new TokenController($accessToken, $storage);
    }

    private function getTestServer()
    {
        $storage = Bootstrap::getInstance()->getMemoryStorage();
        $server = new Server($storage);
        $server->addGrantType(new AuthorizationCode($storage));

        return $server;
    }
}
