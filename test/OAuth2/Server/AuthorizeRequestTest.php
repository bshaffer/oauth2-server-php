<?php

class OAuth2_AuthorizeRequestTest extends PHPUnit_Framework_TestCase
{
    public function testNoClientIdResponse()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $response = $server->handleAuthorizeRequest($request, false);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getResponseParameter('error'), 'invalid_client');
        $this->assertEquals($response->getResponseParameter('error_description'), 'No client id supplied');
    }

    public function testNoRedirectUriSuppliedOrStoredResponse()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $response = $server->handleAuthorizeRequest($request, false);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getResponseParameter('error'), 'invalid_uri');
        $this->assertEquals($response->getResponseParameter('error_description'), 'No redirect URI was supplied or stored');
    }

    public function testNoResponseTypeResponse()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['redirect_uri'] = 'http://adobe.com'; // valid redirect URI
        $response = $server->handleAuthorizeRequest($request, false);

        $this->assertEquals($response->getStatusCode(), 302);
        $this->assertEquals($response->getResponseParameter('error'), 'invalid_request');
        $this->assertEquals($response->getResponseParameter('error_description'), 'Invalid or missing response type');
    }

    public function testInvalidResponseTypeResponse()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['redirect_uri'] = 'http://adobe.com'; // valid redirect URI
        $request->query['response_type'] = 'invalid'; // invalid response type
        $response = $server->handleAuthorizeRequest($request, false);

        $this->assertEquals($response->getStatusCode(), 302);
        $this->assertEquals($response->getResponseParameter('error'), 'invalid_request');
        $this->assertEquals($response->getResponseParameter('error_description'), 'Invalid or missing response type');
    }

    public function testRedirectUriFragmentResponse()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['redirect_uri'] = 'http://adobe.com#fragment'; // valid redirect URI
        $request->query['response_type'] = 'code'; // invalid response type
        $response = $server->handleAuthorizeRequest($request, true);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getResponseParameter('error'), 'invalid_uri');
        $this->assertEquals($response->getResponseParameter('error_description'), 'The redirect URI must not contain a fragment');
    }

    private function getTestServer($config = array())
    {
        $storage = new OAuth2_Storage_Memory(json_decode(file_get_contents(dirname(__FILE__).'/../../config/storage.json'), true));
        $server = new OAuth2_Server($storage, $config);

        // Add the two types supported for authorization grant
        $server->addGrantType(new OAuth2_GrantType_AuthorizationCode($storage));

        return $server;
    }
}