<?php

class OAuth2_RequestTest extends PHPUnit_Framework_TestCase
{
    public function testRequestOverride()
    {
        $request = new OAuth2_Request_TestRequest();
        $server = $this->getTestServer();

        // Smoke test for override request class
        // $response = $server->handleTokenRequest($request);
        // $this->assertInstanceOf('OAuth2_Response', $response);
        // $response = $server->handleAuthorizeRequest($request, true);
        // $this->assertInstanceOf('OAuth2_Response', $response);
        // $response = $server->verifyResourceRequest($request);
        // $this->assertTrue(is_bool($response));

        /*** make some valid requests ***/

        // Valid Token Request
        $request->setPost(array(
            'grant_type' => 'authorization_code',
            'client_id'  => 'Test Client ID',
            'client_secret' => 'TestSecret',
            'code' => 'testcode',
        ));
        $response = $server->handleTokenRequest($request);
        $this->assertEquals($response->getStatusCode(), 200);
        $this->assertNull($response->getParameter('error'));
        $this->assertNotNUll($response->getParameter('access_token'));
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
