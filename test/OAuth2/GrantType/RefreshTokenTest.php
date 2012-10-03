<?php

class OAuth2_GrantType_RefreshTokenTest extends PHPUnit_Framework_TestCase
{
    public function testNoRefreshToken()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'refresh_token'; // valid grant type
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['client_secret'] = 'TestSecret'; // valid client secret
        $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getResponseParameter('error'), 'invalid_request');
        $this->assertEquals($response->getResponseParameter('error_description'), 'Missing parameter: "refresh_token" is required');
    }

    public function testInvalidRefreshToken()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'refresh_token'; // valid grant type
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['client_secret'] = 'TestSecret'; // valid client secret
        $request->query['refresh_token'] = 'fake-token'; // valid client secret
        $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getResponseParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getResponseParameter('error_description'), 'Invalid refresh token');
    }

    public function testValidRefreshToken()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'refresh_token'; // valid grant type
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['client_secret'] = 'TestSecret'; // valid client secret
        $request->query['refresh_token'] = 'test-refreshtoken'; // valid client secret
        $token = $server->grantAccessToken($request);

        $this->assertTrue(isset($token['refresh_token']));
    }

    private function getTestServer()
    {
        $storage = new OAuth2_Storage_Memory(json_decode(file_get_contents(dirname(__FILE__).'/../../config/storage.json'), true));
        $server = new OAuth2_Server($storage);
        $server->addGrantType(new OAuth2_GrantType_RefreshToken($storage));

        return $server;
    }
}