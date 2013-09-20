<?php

namespace OAuth2\ResponseType;

use OAuth2\Server;
use OAuth2\Response;
use OAuth2\Request\TestRequest;
use OAuth2\Storage\Bootstrap;
use OAuth2\Storage\PrivateKey;
use OAuth2\GrantType\AuthorizationCode;
use OAuth2\ResponseType\CryptoToken;

class CryptoTokenTest extends \PHPUnit_Framework_TestCase
{
    public function testValidClientIdScope()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'authorization_code', // valid grant type
            'code'       => 'testcode',
            'client_id' => 'Test Client ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
        ));
        $server->handleTokenRequest($request, $response = new Response());

        $this->assertNotNull($response->getParameter('access_token'));
        $this->assertEquals(2, substr_count($response->getParameter('access_token'), '.'));
    }

    private function getTestServer()
    {
        $memoryStorage = Bootstrap::getInstance()->getMemoryStorage();
        $pubkeyStorage = Bootstrap::getInstance()->getPublicKeyStorage();
        $storage = array(
            'access_token' => $pubkeyStorage,
            'authorization_code' => $memoryStorage,
            'client_credentials' => $memoryStorage,
        );
        $responseTypes = array(
            'token' => new CryptoToken($pubkeyStorage),
        );
        $server = new Server($storage, array(), array(), $responseTypes);
        $server->addGrantType(new AuthorizationCode($memoryStorage));

        return $server;
    }
}
