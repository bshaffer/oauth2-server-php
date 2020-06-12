<?php


namespace OAuth2\OpenID\GrantType;

use OAuth2\Storage\Bootstrap;
use OAuth2\Server;
use OAuth2\Request\TestRequest;
use OAuth2\Response;
use PHPUnit\Framework\TestCase;

class RefreshTokenTest extends TestCase
{
    private $storage;

    private $serverConfig = array(
        'use_openid_connect' => true
    );

    /**
     * Refresh token request must have parameter 'refresh_token'
     * @see Section 12.1 of https://openid.net/specs/openid-connect-core-1_0.html
     */
    public function testNoRefreshToken()
    {
        $server = $this->getTestServer();
        $request = TestRequest::createPost(array(
            'grant_type' => 'refresh_token',
            'client_id' => 'Test Client ID',
            'client_secret' => 'TestSecret'
        ));
        $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_request');
        $this->assertEquals($response->getParameter('error_description'), 'Missing parameter: "refresh_token" is required');
    }

    public function testInvalidRefreshToken()
    {
        $server = $this->getTestServer();
        $server->addGrantType(new RefreshToken($this->storage));

        $request = TestRequest::createPost(array(
            'grant_type' => 'refresh_token',
            'client_id' => 'Test Client ID',
            'client_secret' => 'TestSecret',
            'refresh_token' => 'refresh_token_does_not_exist'
        ));
        $server->grantAccessToken($request, $response = new Response());
    }

    private function getTestServer()
    {
        $this->storage = Bootstrap::getInstance()->getMemoryStorage();

        return new Server($this->storage, $this->serverConfig);
    }
}