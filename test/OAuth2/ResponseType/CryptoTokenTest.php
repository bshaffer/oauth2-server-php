<?php

namespace OAuth2\ResponseType;

use OAuth2\Server;
use OAuth2\Response;
use OAuth2\Request\TestRequest;
use OAuth2\Storage\Bootstrap;
use OAuth2\Storage\CryptoToken as CryptoTokenStorage;
use OAuth2\GrantType\ClientCredentials;
use OAuth2\GrantType\UserCredentials;
use OAuth2\GrantType\RefreshToken;

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

    public function testCryptoTokenWithRefreshToken()
    {
        $server = $this->getTestServer();

        // add "UserCredentials" grant type and "CryptoToken" response type
        // and ensure "CryptoToken" response type has "RefreshToken" storage
        $memoryStorage = Bootstrap::getInstance()->getMemoryStorage();
        $server->addGrantType(new UserCredentials($memoryStorage));
        $server->addGrantType(new RefreshToken($memoryStorage));
        $server->addResponseType(new CryptoToken($memoryStorage, $memoryStorage, $memoryStorage), 'token');

        $request = TestRequest::createPost(array(
            'grant_type'    => 'password',         // valid grant type
            'client_id'     => 'Test Client ID',   // valid client id
            'client_secret' => 'TestSecret',       // valid client secret
            'username'      => 'test-username',    // valid username
            'password'      => 'testpass',         // valid password
        ));

        // make the call to grant a crypto token
        $server->handleTokenRequest($request, $response = new Response());
        $this->assertNotNull($cryptoToken = $response->getParameter('access_token'));
        $this->assertNotNull($refreshToken = $response->getParameter('refresh_token'));

        // decode token and make sure refresh_token isn't set
        list($header, $payload, $signature) = explode('.', $cryptoToken);
        $decodedToken = json_decode(base64_decode($payload), true);
        $this->assertFalse(array_key_exists('refresh_token', $decodedToken));

        // use the refresh token to get another access token
        $request = TestRequest::createPost(array(
            'grant_type'    => 'refresh_token',
            'client_id'     => 'Test Client ID',   // valid client id
            'client_secret' => 'TestSecret',       // valid client secret
            'refresh_token' => $refreshToken,
        ));

        $server->handleTokenRequest($request, $response = new Response());
        $this->assertNotNull($response->getParameter('access_token'));
    }

    private function getTestServer()
    {
        $memoryStorage = Bootstrap::getInstance()->getMemoryStorage();

        $storage = array(
            'access_token' => new CryptoTokenStorage($memoryStorage),
            'client' => $memoryStorage,
            'client_credentials' => $memoryStorage,
        );
        $server = new Server($storage);
        $server->addGrantType(new ClientCredentials($memoryStorage));

        // make the "token" response type a CryptoToken
        $server->addResponseType(new CryptoToken($memoryStorage, $memoryStorage));

        return $server;
    }
}
