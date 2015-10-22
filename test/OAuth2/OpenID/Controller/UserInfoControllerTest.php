<?php

namespace OAuth2\OpenID\Controller;

use OAuth2\Storage\Bootstrap;
use OAuth2\Server;
use Zend\Diactoros\ServerRequestFactory;
use Zend\Diactoros\Response;

class UserInfoControllerTest extends \PHPUnit_Framework_TestCase
{
    public function testCreateController()
    {
        $tokenType = new \OAuth2\TokenType\Bearer();
        $storage = new \OAuth2\Storage\Memory();
        $request = ServerRequestFactory::fromGlobals();
        $controller = new UserInfoController($tokenType, $storage, $storage);

        $response = new Response();
        $controller->handleUserInfoRequest($request, $response);
        $this->assertEquals(401, $response->getStatusCode());
    }

    public function testValidToken()
    {
        $server = $this->getTestServer();
        $request = ServerRequestFactory::fromGlobals();
        $request = $request->withHeader('AUTHORIZATION', 'Bearer accesstoken-openid-connect');
        $response = new Response();

        $server->handleUserInfoRequest($request, $response);
        $parameters = $response->getParameters();
        $this->assertEquals($parameters['sub'], 'testuser');
        $this->assertEquals($parameters['email'], 'testuser@test.com');
        $this->assertEquals($parameters['email_verified'], true);
    }

    private function getTestServer($config = array())
    {
        $storage = Bootstrap::getInstance()->getMemoryStorage();
        $server = new Server($storage, $config);

        return $server;
    }
}
