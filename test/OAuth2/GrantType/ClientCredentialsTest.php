<?php

class OAuth2_GrantType_ClientCredentialsTest extends PHPUnit_Framework_TestCase
{
    public function testInvalidCredentials()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'client_credentials'; // valid grant type
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['client_secret'] = 'FakeSecret'; // valid client secret
        $response = $server->handleGrantRequest($request);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_client');
        $this->assertEquals($response->getParameter('error_description'), 'The client credentials are invalid');
    }

    public function testValidCredentialsWithScope()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'client_credentials'; // valid grant type
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['client_secret'] = 'TestSecret'; // valid client secret
        $request->query['scope'] = 'scope';
        $token = $server->grantAccessToken($request);

        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
        $this->assertArrayHasKey('scope', $token);
        $this->assertEquals($token['scope'], 'scope');
    }

    public function testValidCredentialsNoScope()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'client_credentials'; // valid grant type
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['client_secret'] = 'TestSecret'; // valid client secret
        $token = $server->grantAccessToken($request);

        $this->assertNotNull($token);
        $this->assertArrayHasKey('scope', $token);
        $this->assertNull($token['scope']);
    }

    public function testValidCredentialsInHeader()
    {
        // create with HTTP_AUTHORIZATION in header
        $server = $this->getTestServer();
        $headers = array('HTTP_AUTHORIZATION' => 'Basic '.base64_encode('Test Client ID:TestSecret'));
        $query  = array('grant_type' => 'client_credentials');
        $request = new OAuth2_Request($query, array(), array(), array(), array(), $headers);
        $token = $server->grantAccessToken($request);

        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
        $this->assertNotNull($token['access_token']);

        // create using PHP Authorization Globals
        $headers = array('PHP_AUTH_USER' => 'Test Client ID', 'PHP_AUTH_PW' => 'TestSecret');
        $query  = array('grant_type' => 'client_credentials');
        $request = new OAuth2_Request($query, array(), array(), array(), array(), $headers);
        $token = $server->grantAccessToken($request);

        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
        $this->assertNotNull($token['access_token']);
    }

    public function testValidCredentialsInRequest()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->server['REQUEST_METHOD'] = 'POST';
        $request->query['grant_type'] = 'client_credentials'; // valid grant type
        $request->request['client_id'] = 'Test Client ID'; // valid client id
        $request->request['client_secret'] = 'TestSecret'; // valid client secret
        $token = $server->grantAccessToken($request);

        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
        $this->assertNotNull($token['access_token']);
    }

    public function testValidCredentialsInQuerystring()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'client_credentials'; // valid grant type
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['client_secret'] = 'TestSecret'; // valid client secret
        $token = $server->grantAccessToken($request);

        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
        $this->assertNotNull($token['access_token']);
    }

    private function getTestServer()
    {
        $storage = new OAuth2_Storage_Memory(json_decode(file_get_contents(dirname(__FILE__).'/../../config/storage.json'), true));
        $server = new OAuth2_Server($storage);
        $server->addGrantType(new OAuth2_GrantType_ClientCredentials($storage));

        return $server;
    }
}