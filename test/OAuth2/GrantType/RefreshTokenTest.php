<?php

class OAuth2_GrantType_RefreshTokenTest extends PHPUnit_Framework_TestCase
{
    private $storage;

    public function testNoRefreshToken()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'refresh_token'; // valid grant type
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['client_secret'] = 'TestSecret'; // valid client secret
        $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_request');
        $this->assertEquals($response->getParameter('error_description'), 'Missing parameter: "refresh_token" is required');
    }

    public function testInvalidRefreshToken()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'refresh_token'; // valid grant type
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['client_secret'] = 'TestSecret'; // valid client secret
        $request->query['refresh_token'] = 'fake-token'; // valid client secret
        $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Invalid refresh token');
    }

    public function testValidRefreshToken()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'refresh_token'; // valid grant type
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['client_secret'] = 'TestSecret'; // valid client secret
        $request->query['refresh_token'] = 'test-refreshtoken'; // valid client secret
        $token = $server->grantAccessToken($request);
        $this->assertTrue(isset($token['refresh_token']));

        $refresh_token = $this->storage->getRefreshToken($token['refresh_token']);
        $this->assertNotNull($refresh_token);
        $this->assertEquals($refresh_token['refresh_token'], $token['refresh_token']);
        $this->assertEquals($refresh_token['client_id'], $request->query('client_id'));
    }

    private function getTestServer()
    {
        $this->storage = new OAuth2_Storage_Memory(json_decode(file_get_contents(dirname(__FILE__).'/../../config/storage.json'), true));
        $server = new OAuth2_Server($this->storage);
        $server->addGrantType(new OAuth2_GrantType_RefreshToken($this->storage));

        return $server;
    }
}