<?php

namespace OAuth2\ResponseType;

use OAuth2\Server;
use OAuth2\Response;
use OAuth2\Request\TestRequest;
use OAuth2\Storage\Bootstrap;
use OAuth2\Storage\PrivateKey;
use OAuth2\GrantType\ClientCredentials;
use OAuth2\ResponseType\CryptoToken;

class CryptoTokenTest extends \PHPUnit_Framework_TestCase
{
    public function testGrantCryptoToken()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type'    => 'client_credentials', // valid grant type
            'client_id'     => 'Test Client ID',     // valid client id
            'client_secret' => 'TestSecret',         // valid client secret
        ));
        $server->handleTokenRequest($request, $response = new Response());

        $this->assertNotNull($response->getParameter('access_token'));
        $this->assertEquals(2, substr_count($response->getParameter('access_token'), '.'));
    }

    public function testAccessResourceWithCryptoToken()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type'    => 'client_credentials', // valid grant type
            'client_id'     => 'Test Client ID',     // valid client id
            'client_secret' => 'TestSecret',         // valid client secret
        ));
        $server->handleTokenRequest($request, $response = new Response());
        $this->assertNotNull($cryptoToken = $response->getParameter('access_token'));

        // make a call to the resource server using the crypto token
        $request = TestRequest::createPost(array(
            'access_token' => $cryptoToken,
        ));

        $this->assertTrue($server->verifyResourceRequest($request));
    }

    public function testAccessResourceWithCryptoTokenUsingSecondaryStorage()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type'    => 'client_credentials', // valid grant type
            'client_id'     => 'Test Client ID',     // valid client id
            'client_secret' => 'TestSecret',         // valid client secret
        ));
        $server->handleTokenRequest($request, $response = new Response());
        $this->assertNotNull($cryptoToken = $response->getParameter('access_token'));

        // make a call to the resource server using the crypto token
        $request = TestRequest::createPost(array(
            'access_token' => $cryptoToken,
        ));

        // create a resource server with the "memory" storage from the grant server
        $resourceServer = new Server($server->getStorage('client_credentials'));

        $this->assertTrue($resourceServer->verifyResourceRequest($request));
    }

    private function getTestServer()
    {
        $memoryStorage = Bootstrap::getInstance()->getMemoryStorage();
        $pubkeyStorage = Bootstrap::getInstance()->getPublicKeyStorage($memoryStorage);
        $storage = array(
            'access_token' => $pubkeyStorage,
            'client_credentials' => $memoryStorage,
        );
        $server = new Server($storage);
        $server->addGrantType(new ClientCredentials($memoryStorage));

        // make the "token" response type a CryptoToken
        $server->addResponseType(new CryptoToken($pubkeyStorage));

        return $server;
    }
}
