<?php

class OAuth2_AccessTokenRequestTest extends PHPUnit_Framework_TestCase
{
    public function testNoGrantType()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $response = $server->handleAccessTokenRequest(OAuth2_Request::createFromGlobals());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getResponseParameter('error'), 'invalid_request');
        $this->assertEquals($response->getResponseParameter('error_description'), 'The grant type was not specified in the request');
    }

    public function testInvalidGrantType()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'invalid_grant_type'; // invalid grant type
        $response = $server->handleAccessTokenRequest($request);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getResponseParameter('error'), 'unsupported_grant_type');
        $this->assertEquals($response->getResponseParameter('error_description'), 'Grant type "invalid_grant_type" not supported');
    }

    public function testNoClientId()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'code'; // valid grant type
        $response = $server->handleAccessTokenRequest($request);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getResponseParameter('error'), 'invalid_client');
        $this->assertEquals($response->getResponseParameter('error_description'), 'Client credentials were not found in the headers or body');
    }

    public function testNoClientSecret()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'code'; // valid grant type
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $response = $server->handleAccessTokenRequest($request);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getResponseParameter('error'), 'invalid_client');
        $this->assertEquals($response->getResponseParameter('error_description'), 'Client credentials were not found in the headers or body');
    }

    public function testInvalidClientCredentials()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'code'; // valid grant type
        $request->query['client_id'] = 'Fake Client ID'; // invalid client id
        $request->query['client_secret'] = 'Fake Client Secret'; // invalid client secret
        $response = $server->handleAccessTokenRequest($request);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getResponseParameter('error'), 'invalid_client');
        $this->assertEquals($response->getResponseParameter('error_description'), 'The client credentials are invalid');

        // try again with a real client ID, but an invalid secret
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $response = $server->handleAccessTokenRequest($request);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getResponseParameter('error'), 'invalid_client');
        $this->assertEquals($response->getResponseParameter('error_description'), 'The client credentials are invalid');
    }

    private function getTestServer()
    {
        $storage = new OAuth2_Storage_Memory(json_decode(file_get_contents(dirname(__FILE__).'/../../config/storage.json'), true));
        $server = new OAuth2_Server($storage);
        $server->addGrantType(new OAuth2_GrantType_AuthorizationCode($storage)); // or some other grant type.  This is the simplest

        return $server;
    }
}