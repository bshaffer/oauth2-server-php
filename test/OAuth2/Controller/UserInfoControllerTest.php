<?php

namespace OAuth2\Controller;

use OAuth2\Storage\Bootstrap;
use OAuth2\Server;
use OAuth2\GrantType\AuthorizationCode;
use OAuth2\Request;
use OAuth2\Response;

class UserInfoControllerTest extends \PHPUnit_Framework_TestCase
{

    public function testValidToken()
    {
        $server = $this->getTestServer();
        $request = Request::createFromGlobals();
        $request->headers['AUTHORIZATION'] = 'Bearer accesstoken-openid-connect';
        $response = new Response();
        $server->handleUserInfoRequest($request, $response);
        $parameters = $response->getParameters();
        $this->assertEquals($parameters['sub'], 'test-username');
        $this->assertEquals($parameters['email'], 'testuser@ourdomain.com');
        $this->assertEquals($parameters['email_verified'], false);
    }

    private function getTestServer($config = array())
    {
        $storage = Bootstrap::getInstance()->getMemoryStorage();
        $server = new Server($storage, $config);
        return $server;
    }
}
