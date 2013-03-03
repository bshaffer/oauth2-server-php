<?php

class OAuth2_Server_Authorize_BasicValidationTest extends PHPUnit_Framework_TestCase
{
    public function testNoClientIdResponse()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $response = $server->handleAuthorizeRequest($request, false);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_client');
        $this->assertEquals($response->getParameter('error_description'), 'No client id supplied');
    }

    public function testInvalidClientIdResponse()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['client_id'] = 'Fake Client ID'; // invalid client id
        $response = $server->handleAuthorizeRequest($request, false);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_client');
        $this->assertEquals($response->getParameter('error_description'), 'The client id supplied is invalid');
    }

    public function testNoRedirectUriSuppliedOrStoredResponse()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $response = $server->handleAuthorizeRequest($request, false);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_uri');
        $this->assertEquals($response->getParameter('error_description'), 'No redirect URI was supplied or stored');
    }

    public function testNoResponseTypeResponse()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['redirect_uri'] = 'http://adobe.com'; // valid redirect URI
        $response = $server->handleAuthorizeRequest($request, false);

        $this->assertEquals($response->getStatusCode(), 302);
        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);
        parse_str($parts['query'], $query);

        $this->assertEquals($query['error'], 'invalid_request');
        $this->assertEquals($query['error_description'], 'Invalid or missing response type');
    }

    public function testInvalidResponseTypeResponse()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['redirect_uri'] = 'http://adobe.com'; // valid redirect URI
        $request->query['response_type'] = 'invalid'; // invalid response type
        $response = $server->handleAuthorizeRequest($request, false);

        $this->assertEquals($response->getStatusCode(), 302);
        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);
        parse_str($parts['query'], $query);

        $this->assertEquals($query['error'], 'invalid_request');
        $this->assertEquals($query['error_description'], 'Invalid or missing response type');
    }

    public function testRedirectUriFragmentResponse()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['redirect_uri'] = 'http://adobe.com#fragment'; // valid redirect URI
        $request->query['response_type'] = 'code'; // invalid response type
        $response = $server->handleAuthorizeRequest($request, true);

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_uri');
        $this->assertEquals($response->getParameter('error_description'), 'The redirect URI must not contain a fragment');
    }

    public function testEnforceState()
    {
        $server = $this->getTestServer(array('enforce_state' => true));
        $request = OAuth2_Request::createFromGlobals();
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['redirect_uri'] = 'http://adobe.com'; // valid redirect URI
        $request->query['response_type'] = 'code';
        $response = $server->handleAuthorizeRequest($request, true);

        $this->assertEquals($response->getStatusCode(), 302);
        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);
        parse_str($parts['query'], $query);

        $this->assertEquals($query['error'], 'invalid_request');
        $this->assertEquals($query['error_description'], 'The state parameter is required');
    }

    public function testEnforceScope()
    {
        $server = $this->getTestServer();
        $scopeStorage = new OAuth2_Storage_Memory(array('default_scope' => false, 'supported_scopes' => 'testscope'));
        $server->setScopeUtil(new OAuth2_Scope($scopeStorage));

        $request = OAuth2_Request::createFromGlobals();
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['redirect_uri'] = 'http://adobe.com'; // valid redirect URI
        $request->query['response_type'] = 'code';
        $response = $server->handleAuthorizeRequest($request, true);

        $this->assertEquals($response->getStatusCode(), 302);
        $parts = parse_url($response->getHttpHeader('Location'));
        parse_str($parts['query'], $query);

        $this->assertEquals($query['error'], 'invalid_client');
        $this->assertEquals($query['error_description'], 'This application requires you specify a scope parameter');

        $request->query['scope'] = 'testscope';
        $response = $server->handleAuthorizeRequest($request, true);

        $this->assertEquals($response->getStatusCode(), 302);
        $parts = parse_url($response->getHttpHeader('Location'));
        parse_str($parts['query'], $query);

        // success!
        $this->assertFalse(isset($query['error']));
    }

    public function testValidateRedirectUri()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['client_id'] = 'Test Client ID with Redirect Uri'; // valid client id
        $request->query['redirect_uri'] = 'http://adobe.com'; // invalid redirect URI
        $request->query['response_type'] = 'code';
        $response = $server->handleAuthorizeRequest($request, true);

        $this->assertEquals($response->getStatusCode(), 400);

        $this->assertEquals($response->getParameter('error'), 'redirect_uri_mismatch');
        $this->assertEquals($response->getParameter('error_description'), 'The redirect URI provided is missing or does not match');
    }

    private function getTestServer($config = array())
    {
        $storage = OAuth2_Storage_Bootstrap::getInstance()->getMemoryStorage();
        $server = new OAuth2_Server($storage, $config);

        // Add the two types supported for authorization grant
        $server->addGrantType(new OAuth2_GrantType_AuthorizationCode($storage));

        return $server;
    }
}
