<?php

class OAuth2_Server_Grant_BasicValidationTest extends PHPUnit_Framework_TestCase
{
    public function testNoGrantType()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $response = $server->handleTokenRequest(OAuth2_Request_TestRequest::createPost());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_request');
        $this->assertEquals($response->getParameter('error_description'), 'The grant type was not specified in the request');
    }

    public function testInvalidGrantType()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'invalid_grant_type', // invalid grant type
        ));
        $response = $server->handleTokenRequest($request);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'unsupported_grant_type');
        $this->assertEquals($response->getParameter('error_description'), 'Grant type "invalid_grant_type" not supported');
    }

    public function testNoClientId()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
        ));
        $response = $server->handleTokenRequest($request);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_client');
        $this->assertEquals($response->getParameter('error_description'), 'Client credentials were not found in the headers or body');
    }

    public function testNoClientSecret()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'client_id' => 'Test Client ID', // valid client id
        ));
        $response = $server->handleTokenRequest($request);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_client');
        $this->assertEquals($response->getParameter('error_description'), 'Client credentials were not found in the headers or body');
    }

    public function testInvalidClientCredentials()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'client_id' => 'Fake Client ID', // invalid client id
            'client_secret' => 'Fake Client Secret', // invalid client secret
        ));
        $response = $server->handleTokenRequest($request);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_client');
        $this->assertEquals($response->getParameter('error_description'), 'The client credentials are invalid');

        // try again with a real client ID, but an invalid secret
        $request->request['client_id'] = 'Test Client ID'; // valid client id
        $response = $server->handleTokenRequest($request);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_client');
        $this->assertEquals($response->getParameter('error_description'), 'The client credentials are invalid');
    }

    public function testValidTokenResponse()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'client_id' => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code' => 'testcode', // valid authorization code
        ));
        $response = $server->handleTokenRequest($request);

        $this->assertTrue($response instanceof OAuth2_Response);
        $this->assertEquals($response->getStatusCode(), 200);
        $this->assertNull($response->getParameter('error'));
        $this->assertNull($response->getParameter('error_description'));
        $this->assertNotNUll($response->getParameter('access_token'));
        $this->assertNotNUll($response->getParameter('expires_in'));
        $this->assertNotNUll($response->getParameter('token_type'));
    }

    private function getTestServer()
    {
        $storage = OAuth2_Storage_Bootstrap::getInstance()->getMemoryStorage();
        $server = new OAuth2_Server($storage);
        $server->addGrantType(new OAuth2_GrantType_AuthorizationCode($storage)); // or some other grant type.  This is the simplest

        return $server;
    }
}
