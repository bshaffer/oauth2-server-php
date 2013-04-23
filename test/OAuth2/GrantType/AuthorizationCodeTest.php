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
        $response = $server->handleTokenRequest($request);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_request');
        $this->assertEquals($response->getParameter('error_description'), 'Missing parameter: "code" is required');
    }

    public function testInvalidCode()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'client_id' => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code' => 'InvalidCode', // invalid authorization code
        ));
        $response = $server->handleTokenRequest($request);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Authorization code doesn\'t exist or is invalid for the client');
    }

    public function testCodeCannotBeUsedTwice()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'client_id' => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'code' => 'testcode', // valid code
        ));
        $response = $server->handleTokenRequest($request);

        $this->assertEquals($response->getStatusCode(), 200);
        $this->assertNotNull($response->getParameter('access_token'));

        // try to use the same code again
        $response = $server->handleTokenRequest($request);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Authorization code doesn\'t exist or is invalid for the client');
    }

    private function getTestServer()
    {
        $storage = new OAuth2_Storage_Memory(json_decode(file_get_contents(dirname(__FILE__).'/../../config/storage.json'), true));
        $server = new OAuth2_Server($storage);
        $server->addGrantType(new OAuth2_GrantType_AuthorizationCode($storage));

        return $server;
    }
}
