<?php

class OAuth2_ServerTest extends PHPUnit_Framework_TestCase
{
    /**
     * @expectedException LogicException OAuth2_Storage_ClientInterface
     **/
    public function testGetAuthorizeServerWithNoClientStorageThrowsException()
    {
        // must set Client Storage
        $server = new OAuth2_Server();
        $server->getAuthorizeController();
    }

    /**
     * @expectedException LogicException OAuth2_Storage_AccessTokenInterface
     **/
    public function testGetAuthorizeServerWithNoAccessTokenStorageThrowsException()
    {
        // must set AccessToken or AuthorizationCode
        $server = new OAuth2_Server();
        $server->addStorage($this->getMock('OAuth2_Storage_ClientInterface'));
        $server->getAuthorizeController();
    }

    public function testGetAuthorizeServerWithClientStorageAndAccessTokenResponseType()
    {
        // must set AccessToken or AuthorizationCode
        $server = new OAuth2_Server();
        $server->addStorage($this->getMock('OAuth2_Storage_ClientInterface'));
        $server->addResponseType($this->getMock('OAuth2_ResponseType_AccessTokenInterface'));

        $this->assertNotNull($server->getAuthorizeController());
    }

    public function testGetAuthorizeServerWithClientStorageAndAuthorizationCodeResponseType()
    {
        // must set AccessToken or AuthorizationCode
        $server = new OAuth2_Server();
        $server->addStorage($this->getMock('OAuth2_Storage_ClientInterface'));
        $server->addResponseType($this->getMock('OAuth2_ResponseType_AuthorizationCodeInterface'));

        $this->assertNotNull($server->getAuthorizeController());
    }

    public function testGetAuthorizeServerWithClientStorageAndAccessTokenStorage()
    {
        // must set AccessToken or AuthorizationCode
        $server = new OAuth2_Server();
        $server->addStorage($this->getMock('OAuth2_Storage_ClientInterface'));
        $server->addStorage($this->getMock('OAuth2_Storage_AccessTokenInterface'));

        $this->assertNotNull($server->getAuthorizeController());
    }

    public function testGetAuthorizeServerWithClientStorageAndAuthorizationCodeStorage()
    {
        // must set AccessToken or AuthorizationCode
        $server = new OAuth2_Server();
        $server->addStorage($this->getMock('OAuth2_Storage_ClientInterface'));
        $server->addStorage($this->getMock('OAuth2_Storage_AuthorizationCodeInterface'));

        $this->assertNotNull($server->getAuthorizeController());
    }

    /**
     * @expectedException LogicException OAuth2_Storage_ClientCredentialsInterface
     **/
    public function testGetGrantServerWithNoClientCredentialsStorageThrowsException()
    {
        $server = new OAuth2_Server();
        $server->getGrantController();
    }

    /**
     * @expectedException LogicException OAuth2_Storage_AccessTokenInterface
     **/
    public function testGetGrantServerWithNoAccessTokenStorageThrowsException()
    {
        $server = new OAuth2_Server();
        $server->addStorage($this->getMock('OAuth2_Storage_ClientCredentialsInterface'));
        $server->getGrantController();
    }

    public function testGetGrantServerWithAccessTokenAndClientCredentialsStorage()
    {
        $server = new OAuth2_Server();
        $server->addStorage($this->getMock('OAuth2_Storage_AccessTokenInterface'));
        $server->addStorage($this->getMock('OAuth2_Storage_ClientCredentialsInterface'));
        $server->getGrantController();
    }

    public function testGetGrantServerAccessTokenStorageAndClientCredentialsStorageAndGrantTypes()
    {
        $server = new OAuth2_Server();
        $server->addStorage($this->getMock('OAuth2_Storage_AccessTokenInterface'));
        $server->addStorage($this->getMock('OAuth2_Storage_ClientCredentialsInterface'));
        $server->addGrantType($this->getMockBuilder('OAuth2_GrantType_AuthorizationCode')->disableOriginalConstructor()->getMock());
        $server->getGrantController();
    }

    /**
     * @expectedException LogicException OAuth2_Storage_AccessTokenInterface
     **/
    public function testGetAccessServerWithNoAccessTokenStorageThrowsException()
    {
        $server = new OAuth2_Server();
        $server->getAccessController();
    }

    public function testGetAccessServerWithAccessTokenStorage()
    {
        $server = new OAuth2_Server();
        $server->addStorage($this->getMock('OAuth2_Storage_AccessTokenInterface'));
        $server->getAccessController();
    }
}
