<?php

namespace OAuth2\ResponseType;

use OAuth2\Server;
use OAuth2\Response;
use OAuth2\Request\TestRequest;
use OAuth2\Storage\Bootstrap;
use OAuth2\GrantType\DeviceCode as DeviceCodeGrantType;
use OAuth2\ResponseType\DeviceCode as DeviceCodeResponseType;
#use OAuth2\Storage\JwtAccessToken as JwtAccessTokenStorage;
#use OAuth2\GrantType\ClientCredentials;
#use OAuth2\GrantType\UserCredentials;
#use OAuth2\GrantType\RefreshToken;
#use OAuth2\Encryption\Jwt;

class DeviceCodeTest extends \PHPUnit_Framework_TestCase
{
    protected $server;

    public function setUp()
    {
        $this->server = $this->getTestServer();
        $clientStorage = $this->server->getStorage('client');
        $clientStorage->setClientDetails('test_client_id', null, null, 'device_code device_token');
    }

    public function testCreateDeviceCode()
    {
        $server = $this->getTestServer();
        $responseType = $server->getResponseType('token');

        $deviceCode = $responseType->createDeviceCode('test_client_id');
        $this->assertArrayHasKey('code', $deviceCode);
        $this->assertArrayHasKey('user_code', $deviceCode);
        $this->assertArrayHasKey('expires_in', $deviceCode);
        $this->assertArrayHasKey('interval', $deviceCode);
        $this->assertArrayHasKey('verification_uri', $deviceCode);

        $this->assertEquals('http://mysite.com/device', $deviceCode['verification_uri']);
        #$this->assertEquals('test_client_id', $deviceCode['client_id']);
    }

    public function testGrantDeviceCode()
    {
        // add the test parameters in memory
        $request = TestRequest::createPost(array(
            'grant_type'    => 'device_code', // valid grant type
            'client_id'     => 'test_client_id',     // valid client id
        ));
        $this->server->handleDeviceRequest($request, $response = new Response());
        $this->assertNotNull($response->getParameter('code'));
        $this->assertNotNull($response->getParameter('user_code'));
        $this->assertNotNull($response->getParameter('interval'));
        $this->assertNotNull($response->getParameter('verification_uri'));
        $this->assertNotNull($response->getParameter('expires_in'));
    }

    public function testGrantCodeAccessTokenOnNewCode()
    {
        $request = TestRequest::createPost(array(
            'grant_type'    => 'device_code', // valid grant type
            'client_id'     => 'test_client_id',     // valid client id
        ));
        $this->server->handleDeviceRequest($request, $response = new Response());
        $this->assertNotNull($response->getParameter('code'));
        $deviceCodeResponse = $response;

        // Get access token when user_id is null
        $request = TestRequest::createPost(array(
            'grant_type'    => 'device_token', // valid grant type
            'client_id'     => 'test_client_id',     // valid client id
            'code'          => $deviceCodeResponse->getParameter('code'),
        ));
        $this->server->handleDeviceRequest($request, $response = new Response());
        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertArrayHasKey('error', $response->getParameters());
        $this->assertEquals('authorization_pending', $response->getParameter('error'));

        // Update user_id and verify response
        $deviceStorage = $this->server->getStorage('device_code');
        $code = $deviceStorage->getDeviceCode($deviceCodeResponse->getParameter('code'), 'test_client_id');
        $deviceStorage->setDeviceCode(
            $code['device_code'],
            $code['user_code'],
            $code['client_id'],
            1, //assign fake user_id
            $code['expires'],
            $code['scope']
        );

        $request = TestRequest::createPost(array(
            'grant_type'    => 'device_token', // valid grant type
            'client_id'     => 'test_client_id',     // valid client id
            'code'          => $deviceCodeResponse->getParameter('code'),
        ));
        $this->server->handleDeviceRequest($request, $response = new Response());
        $this->assertEquals($response->getStatusCode(), 200);
        $this->assertArrayHasKey('access_token', $response->getParameters());
    }

    private function getTestServer()
    {
        $memoryStorage = Bootstrap::getInstance()->getMemoryStorage();

        $storage = array(
            'access_token' => $memoryStorage,
            'client' => $memoryStorage,
            'device_code' => $memoryStorage,
        );
        $server = new Server($storage);

        // make the "token" response type a DeviceCode response type
        $config = array(
                'interval' => 5,
                'verification_uri' => 'http://mysite.com/device',
        );
        $rsp = new DeviceCodeResponseType($memoryStorage, $config);
        $server->addResponseType($rsp);

        return $server;
    }
}
