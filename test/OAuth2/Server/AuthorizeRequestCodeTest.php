<?php

class OAuth2_AuthorizeRequestCodeTest extends PHPUnit_Framework_TestCase
{
    public function testUserDeniesAccessResponse()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['redirect_uri'] = 'http://adobe.com'; // valid redirect URI
        $request->query['response_type'] = 'code'; // invalid response type
        $response = $server->handleAuthorizeRequest($request, false);

        $this->assertEquals($response->getStatusCode(), 302);
        $this->assertEquals($response->getResponseParameter('error'), 'access_denied');
        $this->assertEquals($response->getResponseParameter('error_description'), 'The user denied access to your application');
    }

    public function testCodeQueryParamIsSet()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = OAuth2_Request::createFromGlobals();
        $request->query['client_id'] = 'Test Client ID'; // valid client id
        $request->query['redirect_uri'] = 'http://adobe.com'; // valid redirect URI
        $request->query['response_type'] = 'code'; // invalid response type
        $response = $server->handleAuthorizeRequest($request, true);

        $this->assertEquals($response->getStatusCode(), 302);
        $this->assertNull($response->getResponseParameter('error'));
        $this->assertNull($response->getResponseParameter('error_description'));

        $location = $response->getHttpHeader('Location');
        $parts = parse_url($location);

        $this->assertEquals('http', $parts['scheme']); // same as passed in to redirect_uri
        $this->assertEquals('adobe.com', $parts['host']); // same as passed in to redirect_uri
        $this->assertArrayHasKey('query', $parts);
        $this->assertFalse(isset($parts['fragment']));

        // assert fragment is in "application/x-www-form-urlencoded" format
        parse_str($parts['query'], $params);
        $this->assertNotNull($params);
        $this->assertArrayHasKey('code', $params);
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