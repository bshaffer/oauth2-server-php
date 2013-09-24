<?php

namespace OAuth2;

use OAuth2\Request\TestRequest;
use OAuth2\Storage\Bootstrap;
use OAuth2\GrantType\AuthorizationCode;

class RequestTest extends \PHPUnit_Framework_TestCase
{
    public function testRequestOverride()
    {
        $request = new TestRequest();
        $server = $this->getTestServer();

        // Smoke test for override request class
        // $server->handleTokenRequest($request, $response = new Response());
        // $this->assertInstanceOf('Response', $response);
        // $server->handleAuthorizeRequest($request, $response = new Response(), true);
        // $this->assertInstanceOf('Response', $response);
        // $response = $server->verifyResourceRequest($request, $response = new Response());
        // $this->assertTrue(is_bool($response));

        /*** make some valid requests ***/

        // Valid Token Request
        $request->setPost(array(
            'grant_type' => 'authorization_code',
            'client_id'  => 'Test Client ID',
            'client_secret' => 'TestSecret',
            'code' => 'testcode',
        ));
        $server->handleTokenRequest($request, $response = new Response());
        $this->assertEquals($response->getStatusCode(), 200);
        $this->assertNull($response->getParameter('error'));
        $this->assertNotNUll($response->getParameter('access_token'));
    }

    private function getTestServer($config = array())
    {
        $storage = Bootstrap::getInstance()->getMemoryStorage();
        $server = new Server($storage, $config);

        // Add the two types supported for authorization grant
        $server->addGrantType(new AuthorizationCode($storage));

        return $server;
    }
}
