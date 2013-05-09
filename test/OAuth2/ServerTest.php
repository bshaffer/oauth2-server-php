<?php

class OAuth2_ServerTest extends PHPUnit_Framework_TestCase
{
    /**
     * @expectedException LogicException OAuth2_Storage_ClientInterface
     **/
    public function testGetAuthorizeControllerWithNoClientStorageThrowsException()
    {
        // must set Client Storage
        $server = new OAuth2_Server();
        $server->getAuthorizeController();
    }

    /**
     * @expectedException LogicException OAuth2_Storage_AccessTokenInterface
     **/
    public function testGetAuthorizeControllerWithNoAccessTokenStorageThrowsException()
    {
        // must set AccessToken or AuthorizationCode
        $server = new OAuth2_Server();
        $server->addStorage($this->getMock('OAuth2_Storage_ClientInterface'));
        $server->getAuthorizeController();
    }

    public function testGetAuthorizeControllerWithClientStorageAndAccessTokenResponseType()
    {
        // must set AccessToken or AuthorizationCode
        $server = new OAuth2_Server();
        $server->addStorage($this->getMock('OAuth2_Storage_ClientInterface'));
        $server->addResponseType($this->getMock('OAuth2_ResponseType_AccessTokenInterface'));

        $this->assertNotNull($server->getAuthorizeController());
    }

    public function testGetAuthorizeControllerWithClientStorageAndAuthorizationCodeResponseType()
    {
        // must set AccessToken or AuthorizationCode
        $server = new OAuth2_Server();
        $server->addStorage($this->getMock('OAuth2_Storage_ClientInterface'));
        $server->addResponseType($this->getMock('OAuth2_ResponseType_AuthorizationCodeInterface'));

        $this->assertNotNull($server->getAuthorizeController());
    }

    public function testGetAuthorizeControllerWithClientStorageAndAccessTokenStorage()
    {
        // must set AccessToken or AuthorizationCode
        $server = new OAuth2_Server();
        $server->addStorage($this->getMock('OAuth2_Storage_ClientInterface'));
        $server->addStorage($this->getMock('OAuth2_Storage_AccessTokenInterface'));

        $this->assertNotNull($server->getAuthorizeController());
    }

    public function testGetAuthorizeControllerWithClientStorageAndAuthorizationCodeStorage()
    {
        // must set AccessToken or AuthorizationCode
        $server = new OAuth2_Server();
        $server->addStorage($this->getMock('OAuth2_Storage_ClientInterface'));
        $server->addStorage($this->getMock('OAuth2_Storage_AuthorizationCodeInterface'));

        $this->assertNotNull($server->getAuthorizeController());
    }

    /**
     * @expectedException LogicException grant_types
     **/
    public function testGetTokenControllerWithGrantTypeStorageThrowsException()
    {
        $server = new OAuth2_Server();
        $server->getTokenController();
    }

    /**
     * @expectedException LogicException OAuth2_Storage_ClientCredentialsInterface
     **/
    public function testGetTokenControllerWithNoClientCredentialsStorageThrowsException()
    {
        $server = new OAuth2_Server();
        $server->addStorage($this->getMock('OAuth2_Storage_UserCredentialsInterface'));
        $server->getTokenController();
    }

    /**
     * @expectedException LogicException OAuth2_Storage_AccessTokenInterface
     **/
    public function testGetTokenControllerWithNoAccessTokenStorageThrowsException()
    {
        $server = new OAuth2_Server();
        $server->addStorage($this->getMock('OAuth2_Storage_ClientCredentialsInterface'));
        $server->getTokenController();
    }

    public function testGetTokenControllerWithAccessTokenAndClientCredentialsStorage()
    {
        $server = new OAuth2_Server();
        $server->addStorage($this->getMock('OAuth2_Storage_AccessTokenInterface'));
        $server->addStorage($this->getMock('OAuth2_Storage_ClientCredentialsInterface'));
        $server->getTokenController();
    }

    public function testGetTokenControllerAccessTokenStorageAndClientCredentialsStorageAndGrantTypes()
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
    public function testGetResourceControllerWithNoAccessTokenStorageThrowsException()
    {
        $server = new OAuth2_Server();
        $server->getResourceController();
    }

    public function testGetResourceControllerWithAccessTokenStorage()
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
        $server->addStorage(new StdClass());
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

    public function testAddingResponseType()
    {
        $storage = $this->getMock('OAuth2_Storage_Memory');
        $storage
          ->expects($this->any())
          ->method('getClientDetails')
          ->will($this->returnValue(array('client_id' => 'some_client')));
        $storage
          ->expects($this->any())
          ->method('checkRestrictedGrantType')
          ->will($this->returnValue(TRUE));

        // add with the "code" key explicitly set
        $codeType = new OAuth2_ResponseType_AuthorizationCode($storage);
        $server = new OAuth2_Server();
        $server->addStorage($storage);
        $server->addResponseType($codeType);
        $request = new OAuth2_Request(array('response_type' => 'code', 'client_id' => 'some_client', 'redirect_uri' => 'http://example.com'));
        $server->handleAuthorizeRequest($request, $response = new OAuth2_Response(), true);

        // the response is successful
        $this->assertEquals($response->getStatusCode(), 302);
        $parts = parse_url($response->getHttpHeader('Location'));
        parse_str($parts['query'], $query);
        $this->assertTrue(isset($query['code']));
        $this->assertFalse(isset($query['error']));

        // add with the "code" key not set
        $codeType = new OAuth2_ResponseType_AuthorizationCode($storage);
        $server = new OAuth2_Server(array($storage), array(), array(), array($codeType));
        $request = new OAuth2_Request(array('response_type' => 'code', 'client_id' => 'some_client', 'redirect_uri' => 'http://example.com'));
        $server->handleAuthorizeRequest($request, $response = new OAuth2_Response(), true);

        // the response is successful
        $this->assertEquals($response->getStatusCode(), 302);
        $parts = parse_url($response->getHttpHeader('Location'));
        parse_str($parts['query'], $query);
        $this->assertTrue(isset($query['code']));
        $this->assertFalse(isset($query['error']));
    }

    /**
     * @expectedException InvalidArgumentException OAuth2_ResponseType_AuthorizationCodeInterface
     **/
    public function testAddingUnknownResponseTypeThrowsException()
    {
        $server = new OAuth2_Server();
        $server->addResponseType($this->getMock('OAuth2_ResponseTypeInterface'));
    }

}
