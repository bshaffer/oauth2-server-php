<?php

class OAuth2_GrantType_UserCredentialsTest extends PHPUnit_Framework_TestCase
{
    public function testNoUsername()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'password'; // valid grant type
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['client_secret'] = 'TestSecret'; // valid client secret
        $request->query['password'] = 'testpass'; // valid password
        $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_request');
        $this->assertEquals($response->getParameter('error_description'), 'Missing parameters: "username" and "password" required');
    }

    public function testNoPassword()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'password'; // valid grant type
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['client_secret'] = 'TestSecret'; // valid client secret
        $request->query['username'] = 'test-username'; // valid username
        $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_request');
        $this->assertEquals($response->getParameter('error_description'), 'Missing parameters: "username" and "password" required');
    }

    public function testInvalidUsername()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'password'; // valid grant type
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['client_secret'] = 'TestSecret'; // valid client secret
        $request->query['username'] = 'fake-username'; // valid username
        $request->query['password'] = 'testpass'; // valid password
        $ret = $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Invalid username and password combination');
    }

    public function testInvalidPassword()
    {
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['grant_type'] = 'password'; // valid grant type
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['client_secret'] = 'TestSecret'; // valid client secret
        $request->query['username'] = 'test-username'; // valid username
        $request->query['password'] = 'fakepass'; // valid password
        $ret = $server->grantAccessToken($request);
        $response = $server->getResponse();

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_grant');
        $this->assertEquals($response->getParameter('error_description'), 'Invalid username and password combination');
    }

    private function getTestServer()
    {
        $storage = new OAuth2_Storage_Memory(json_decode(file_get_contents(dirname(__FILE__).'/../../config/storage.json'), true));
        $server = new OAuth2_Server($storage);
        $server->addGrantType(new OAuth2_GrantType_UserCredentials($storage));

        return $server;
    }
}