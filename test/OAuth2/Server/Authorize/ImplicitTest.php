<?php

class OAuth2_Server_Authorize_ImplicitTest extends PHPUnit_Framework_TestCase
{
    public function testImplicitNotAllowedResponse()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['redirect_uri'] = 'http://adobe.com'; // valid redirect URI
        $request->query['response_type'] = 'token'; // invalid response type
        $response = $server->handleAuthorizeRequest($request, false);

        $this->assertEquals($response->getStatusCode(), 302);
        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);
        parse_str($parts['query'], $query);

        $this->assertEquals($query['error'], 'unsupported_response_type');
        $this->assertEquals($query['error_description'], 'implicit grant type not supported');
    }

    public function testUserDeniesAccessResponse()
    {
        $server = $this->getTestServer(array('allow_implicit' => true));
        $request = OAuth2_Request::createFromGlobals();
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['redirect_uri'] = 'http://adobe.com'; // valid redirect URI
        $request->query['response_type'] = 'token'; // invalid response type
        $response = $server->handleAuthorizeRequest($request, false);

        $this->assertEquals($response->getStatusCode(), 302);
        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);
        parse_str($parts['query'], $query);

        $this->assertEquals($query['error'], 'access_denied');
        $this->assertEquals($query['error_description'], 'The user denied access to your application');
    }

    public function testSuccessfulRequestFragmentParameter()
    {
        $server = $this->getTestServer(array('allow_implicit' => true));
        $request = OAuth2_Request::createFromGlobals();
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['redirect_uri'] = 'http://adobe.com'; // valid redirect URI
        $request->query['response_type'] = 'token'; // invalid response type
        $response = $server->handleAuthorizeRequest($request, true);

        $this->assertEquals($response->getStatusCode(), 302);
        $this->assertNull($response->getParameter('error'));
        $this->assertNull($response->getParameter('error_description'));

        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);

        $this->assertEquals('http', $parts['scheme']); // same as passed in to redirect_uri
        $this->assertEquals('adobe.com', $parts['host']); // same as passed in to redirect_uri
        $this->assertArrayHasKey('fragment', $parts);
        $this->assertFalse(isset($parts['query']));

        // assert fragment is in "application/x-www-form-urlencoded" format
        parse_str($parts['fragment'], $params);
        $this->assertNotNull($params);
        $this->assertArrayHasKey('access_token', $params);
        $this->assertArrayHasKey('expires_in', $params);
        $this->assertArrayHasKey('token_type', $params);
    }

    public function testSuccessfulRequestReturnsStateParameter()
    {
        $server = $this->getTestServer(array('allow_implicit' => true));
        $request = OAuth2_Request::createFromGlobals();
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['redirect_uri'] = 'http://adobe.com'; // valid redirect URI
        $request->query['response_type'] = 'token'; // invalid response type
        $request->query['state'] = 'test'; // valid state string (just needs to be passed back to us)
        $response = $server->handleAuthorizeRequest($request, true);

        $this->assertEquals($response->getStatusCode(), 302);
        $this->assertNull($response->getParameter('error'));
        $this->assertNull($response->getParameter('error_description'));

        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);
        $this->assertArrayHasKey('fragment', $parts);
        parse_str($parts['fragment'], $params);

        $this->assertArrayHasKey('state', $params);
        $this->assertEquals($params['state'], 'test');
    }

    public function testSuccessfulRequestStripsExtraParameters()
    {
        $server = $this->getTestServer(array('allow_implicit' => true));
        $request = OAuth2_Request::createFromGlobals();
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['redirect_uri'] = 'http://adobe.com?fake=something'; // valid redirect URI
        $request->query['response_type'] = 'token'; // invalid response type
        $request->query['state'] = 'test'; // valid state string (just needs to be passed back to us)
        $request->query['fake'] = 'something'; // add extra param to querystring
        $response = $server->handleAuthorizeRequest($request, true);

        $this->assertEquals($response->getStatusCode(), 302);
        $this->assertNull($response->getParameter('error'));
        $this->assertNull($response->getParameter('error_description'));

        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);
        $this->assertFalse(isset($parts['fake']));
        $this->assertArrayHasKey('fragment', $parts);
        parse_str($parts['fragment'], $params);

        $this->assertFalse(isset($parmas['fake']));
        $this->assertArrayHasKey('state', $params);
        $this->assertEquals($params['state'], 'test');
    }

    private function getTestServer($config = array())
    {
        $storage = new OAuth2_Storage_Memory(json_decode(file_get_contents(dirname(__FILE__).'/../../../config/storage.json'), true));
        $server = new OAuth2_Server($storage, $config);

        // Add the two types supported for authorization grant
        $server->addGrantType(new OAuth2_GrantType_AuthorizationCode($storage));

        return $server;
    }
}