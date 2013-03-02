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
        $server->getTokenController();
    }

    /**
     * @expectedException LogicException OAuth2_Storage_AccessTokenInterface
     **/
    public function testGetGrantServerWithNoAccessTokenStorageThrowsException()
    {
        $server = new OAuth2_Server();
        $server->addStorage($this->getMock('OAuth2_Storage_ClientCredentialsInterface'));
        $server->getTokenController();
    }

    public function testGetGrantServerWithAccessTokenAndClientCredentialsStorage()
    {
        $server = new OAuth2_Server();
        $server->addStorage($this->getMock('OAuth2_Storage_AccessTokenInterface'));
        $server->addStorage($this->getMock('OAuth2_Storage_ClientCredentialsInterface'));
        $server->getTokenController();
    }

    public function testGetGrantServerAccessTokenStorageAndClientCredentialsStorageAndGrantTypes()
    {
        $server = new OAuth2_Server();
        $server->addStorage($this->getMock('OAuth2_Storage_AccessTokenInterface'));
        $server->addStorage($this->getMock('OAuth2_Storage_ClientCredentialsInterface'));
        $server->addGrantType($this->getMockBuilder('OAuth2_GrantType_AuthorizationCode')->disableOriginalConstructor()->getMock());
        $server->getTokenController();
    }

    /**
     * @expectedException LogicException OAuth2_Storage_AccessTokenInterface
     **/
    public function testGetAccessServerWithNoAccessTokenStorageThrowsException()
    {
        $server = new OAuth2_Server();
        $server->getResourceController();
    }

    public function testGetAccessServerWithAccessTokenStorage()
    {
        $server = new OAuth2_Server();
        $server->addStorage($this->getMock('OAuth2_Storage_AccessTokenInterface'));
        $server->getResourceController();
    }

    /**
     * @expectedException InvalidArgumentException OAuth2_Storage_AccessTokenInterface
     **/
    public function testAddingStorageWithInvalidClass()
    {
        $server = new OAuth2_Server();
        $server->addStorage($this->getMock('OAuth2_ScopeInterface'));
    }

    /**
     * @expectedException InvalidArgumentException access_token
     **/
    public function testAddingStorageWithInvalidKey()
    {
        $server = new OAuth2_Server();
        $server->addStorage($this->getMock('OAuth2_Storage_AccessTokenInterface'), 'nonexistant_storage');
    }

    /**
     * @expectedException InvalidArgumentException OAuth2_Storage_AuthorizationCodeInterface
     **/
    public function testAddingStorageWithInvalidKeyStorageCombination()
    {
        $server = new OAuth2_Server();
        $server->addStorage($this->getMock('OAuth2_Storage_AccessTokenInterface'), 'authorization_code');
    }

    public function testAddingStorageWithValidKeyOnlySetsThatKey()
    {
        if (version_compare(phpversion(), '5.3', '<')) {
            // cannot run this test in 5.2
            return;
        }

        $server = new OAuth2_Server();
        $server->addStorage($this->getMock('OAuth2_Storage_Memory'), 'access_token');

        $reflection = new ReflectionClass($server);
        $prop = $reflection->getProperty('storages');
        $prop->setAccessible(true);

        $storages = $prop->getValue($server); // get the private "storages" property

        $this->assertEquals(1, count($storages));
        $this->assertTrue(isset($storages['access_token']));
        $this->assertFalse(isset($storages['authorization_code']));
    }
}
