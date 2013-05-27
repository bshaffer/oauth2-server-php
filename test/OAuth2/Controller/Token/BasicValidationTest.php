<?php

class OAuth2_Controller_Token_BasicValidationTest extends PHPUnit_Framework_TestCase
{
    public function testNoGrantType()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $server->handleTokenRequest(OAuth2_Request_TestRequest::createPost(), $response = new OAuth2_Response());

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
        $server->handleTokenRequest($request, $response = new OAuth2_Response());

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
            'code'       => 'testcode',
        ));
        $server->handleTokenRequest($request, $response = new OAuth2_Response());

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
            'code'       => 'testcode',
            'client_id' => 'Test Client ID', // valid client id
        ));
        $server->handleTokenRequest($request, $response = new OAuth2_Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_client');
        $this->assertEquals($response->getParameter('error_description'), 'Client credentials were not found in the headers or body');
    }

    public function testInvalidClientId()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'code'       => 'testcode',
            'client_id'  => 'Fake Client ID', // invalid client id
            'client_secret' => 'TestSecret', // valid client secret
        ));
        $server->handleTokenRequest($request, $response = new OAuth2_Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_client');
        $this->assertEquals($response->getParameter('error_description'), 'The client credentials are invalid');
    }

    public function testInvalidClientSecret()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'code'       => 'testcode',
            'client_id'  => 'Test Client ID', // valid client id
            'client_secret' => 'Fake Client Secret', // invalid client secret
        ));
        $server->handleTokenRequest($request, $response = new OAuth2_Response());

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
        $server->handleTokenRequest($request, $response = new OAuth2_Response());

        $this->assertTrue($response instanceof OAuth2_Response);
        $this->assertEquals($response->getStatusCode(), 200);
        $this->assertNull($response->getParameter('error'));
        $this->assertNull($response->getParameter('error_description'));
        $this->assertNotNUll($response->getParameter('access_token'));
        $this->assertNotNUll($response->getParameter('expires_in'));
        $this->assertNotNUll($response->getParameter('token_type'));
    }

    public function testValidClientIdScope()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
                'grant_type' => 'authorization_code', // valid grant type
                'code'       => 'testcode',
                'client_id' => 'Test Client ID', // valid client id
                'client_secret' => 'TestSecret', // valid client secret
                'scope' => 'clientscope1 clientscope2 scope1 scope2 scope3'
        ));
        $server->handleTokenRequest($request, $response = new OAuth2_Response());

        $this->assertEquals($response->getStatusCode(), 200);
        $this->assertNull($response->getParameter('error'));
        $this->assertNull($response->getParameter('error_description'));
        $this->assertEquals('clientscope1 clientscope2 scope1 scope2 scope3', $response->getParameter('scope'));
    }

    public function testInvalidClientIdScope()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = OAuth2_Request_TestRequest::createPost(array(
                'grant_type' => 'authorization_code', // valid grant type
                'code'       => 'testcode',
                'client_id' => 'Test Client ID', // valid client id
                'client_secret' => 'TestSecret', // valid client secret
                'scope' => 'clientscope3 scope1'
        ));
        $server->handleTokenRequest($request, $response = new OAuth2_Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_scope');
        $this->assertEquals($response->getParameter('error_description'), 'An unsupported scope was requested.');
    }

    private function getTestServer()
    {
        $storage = OAuth2_Storage_Bootstrap::getInstance()->getMemoryStorage();
        $server = new OAuth2_Server($storage);
        $server->addGrantType(new OAuth2_GrantType_AuthorizationCode($storage)); // or some other grant type.  This is the simplest

        return $server;
    }
}
