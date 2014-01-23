<?php

namespace OAuth2\ResponseType;

use OAuth2\Server;
use OAuth2\Request;
use OAuth2\Response;
use OAuth2\Storage\Bootstrap;
use OAuth2\GrantType\ClientCredentials;

class IdTokenTest extends \PHPUnit_Framework_TestCase
{
    public function testValidateAuthorizeRequest()
    {
        // add the test parameters in memory
        $server = $this->getTestServer(array('allow_implicit' => true));
        $request = new Request(array(
            'response_type' => 'id_token',
            'redirect_uri'  => 'http://adobe.com',
            'client_id'     => 'Test Client ID',
            'scope'         => 'openid',
            'state'         => 'test',
        ));

        $valid = $server->validateAuthorizeRequest($request, $response = new Response());

        $this->assertTrue($valid);
    }

    public function testHandleAuthorizeRequest()
    {
        // add the test parameters in memory
        $server = $this->getTestServer(array('allow_implicit' => true));
        $request = new Request(array(
            'response_type' => 'id_token',
            'redirect_uri'  => 'http://adobe.com',
            'client_id'     => 'Test Client ID',
            'scope'         => 'openid',
            'state'         => 'test',
        ));

        $server->handleAuthorizeRequest($request, $response = new Response(), true);

        $this->assertEquals($response->getStatusCode(), 302);
        $location = $response->getHttpHeader('Location');
        $this->assertNotContains('error', $location);

        $this->assertArrayHasKey('fragment', $parts);
        $this->assertFalse(isset($parts['query']));

        // assert fragment is in "application/x-www-form-urlencoded" format
        parse_str($parts['fragment'], $params);
        $this->assertNotNull($params);
        $this->assertArrayHasKey('id_token', $params);
        $this->assertArrayNotHasKey('access_token', $params);
    }

    private function getTestServer($config = array())
    {
        $memoryStorage = Bootstrap::getInstance()->getMemoryStorage();
        $memoryStorage->supportedScopes[] = 'openid';

        $storage = array(
            'access_token' => $memoryStorage,
            'client' => $memoryStorage,
            'scope' => $memoryStorage,
        );

        $server = new Server($storage, $config);
        $server->addGrantType(new ClientCredentials($memoryStorage));

        // make the "token" response type an IdToken
        $server->addResponseType(new IdToken($memoryStorage, $memoryStorage, null, array('issuer' => 'test')));

        return $server;
    }
}
