<?php

namespace OAuth2;

use OAuth2\Request\TestRequest;
use OAuth2\ResponseType\AuthorizationCode;
use OAuth2\Storage\Bootstrap;

class ServerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @expectedException LogicException OAuth2\Storage\ClientInterface
     **/
    public function testGetAuthorizeControllerWithNoClientStorageThrowsException()
    {
        // must set Client Storage
        $server = new Server();
        $server->getAuthorizeController();
    }

    /**
     * @expectedException LogicException OAuth2\Storage\AccessTokenInterface
     **/
    public function testGetAuthorizeControllerWithNoAccessTokenStorageThrowsException()
    {
        // must set AccessToken or AuthorizationCode
        $server = new Server();
        $server->addStorage($this->getMock('OAuth2\Storage\ClientInterface'));
        $server->getAuthorizeController();
    }

    public function testGetAuthorizeControllerWithClientStorageAndAccessTokenResponseType()
    {
        // must set AccessToken or AuthorizationCode
        $server = new Server();
        $server->addStorage($this->getMock('OAuth2\Storage\ClientInterface'));
        $server->addResponseType($this->getMock('OAuth2\ResponseType\AccessTokenInterface'));

        $this->assertNotNull($server->getAuthorizeController());
    }

    public function testGetAuthorizeControllerWithClientStorageAndAuthorizationCodeResponseType()
    {
        // must set AccessToken or AuthorizationCode
        $server = new Server();
        $server->addStorage($this->getMock('OAuth2\Storage\ClientInterface'));
        $server->addResponseType($this->getMock('OAuth2\ResponseType\AuthorizationCodeInterface'));

        $this->assertNotNull($server->getAuthorizeController());
    }

    public function testGetAuthorizeControllerWithClientStorageAndAccessTokenStorage()
    {
        // must set AccessToken or AuthorizationCode
        $server = new Server();
        $server->addStorage($this->getMock('OAuth2\Storage\ClientInterface'));
        $server->addStorage($this->getMock('OAuth2\Storage\AccessTokenInterface'));

        $this->assertNotNull($server->getAuthorizeController());
    }

    public function testGetAuthorizeControllerWithClientStorageAndAuthorizationCodeStorage()
    {
        // must set AccessToken or AuthorizationCode
        $server = new Server();
        $server->addStorage($this->getMock('OAuth2\Storage\ClientInterface'));
        $server->addStorage($this->getMock('OAuth2\Storage\AuthorizationCodeInterface'));

        $this->assertNotNull($server->getAuthorizeController());
    }

    /**
     * @expectedException LogicException grant_types
     **/
    public function testGetTokenControllerWithGrantTypeStorageThrowsException()
    {
        $server = new Server();
        $server->getTokenController();
    }

    /**
     * @expectedException LogicException OAuth2\Storage\ClientCredentialsInterface
     **/
    public function testGetTokenControllerWithNoClientCredentialsStorageThrowsException()
    {
        $server = new Server();
        $server->addStorage($this->getMock('OAuth2\Storage\UserCredentialsInterface'));
        $server->getTokenController();
    }

    /**
     * @expectedException LogicException OAuth2\Storage\AccessTokenInterface
     **/
    public function testGetTokenControllerWithNoAccessTokenStorageThrowsException()
    {
        $server = new Server();
        $server->addStorage($this->getMock('OAuth2\Storage\ClientCredentialsInterface'));
        $server->getTokenController();
    }

    public function testGetTokenControllerWithAccessTokenAndClientCredentialsStorage()
    {
        $server = new Server();
        $server->addStorage($this->getMock('OAuth2\Storage\AccessTokenInterface'));
        $server->addStorage($this->getMock('OAuth2\Storage\ClientCredentialsInterface'));
        $server->getTokenController();
    }

    public function testGetTokenControllerAccessTokenStorageAndClientCredentialsStorageAndGrantTypes()
    {
        $server = new Server();
        $server->addStorage($this->getMock('OAuth2\Storage\AccessTokenInterface'));
        $server->addStorage($this->getMock('OAuth2\Storage\ClientCredentialsInterface'));
        $server->addGrantType($this->getMockBuilder('OAuth2\GrantType\AuthorizationCode')->disableOriginalConstructor()->getMock());
        $server->getTokenController();
    }

    /**
     * @expectedException LogicException OAuth2\Storage\AccessTokenInterface
     **/
    public function testGetResourceControllerWithNoAccessTokenStorageThrowsException()
    {
        $server = new Server();
        $server->getResourceController();
    }

    public function testGetResourceControllerWithAccessTokenStorage()
    {
        $server = new Server();
        $server->addStorage($this->getMock('OAuth2\Storage\AccessTokenInterface'));
        $server->getResourceController();
    }

    /**
     * @expectedException InvalidArgumentException OAuth2\Storage\AccessTokenInterface
     **/
    public function testAddingStorageWithInvalidClass()
    {
        $server = new Server();
        $server->addStorage(new \StdClass());
    }

    /**
     * @expectedException InvalidArgumentException access_token
     **/
    public function testAddingStorageWithInvalidKey()
    {
        $server = new Server();
        $server->addStorage($this->getMock('OAuth2\Storage\AccessTokenInterface'), 'nonexistant_storage');
    }

    /**
     * @expectedException InvalidArgumentException OAuth2\Storage\AuthorizationCodeInterface
     **/
    public function testAddingStorageWithInvalidKeyStorageCombination()
    {
        $server = new Server();
        $server->addStorage($this->getMock('OAuth2\Storage\AccessTokenInterface'), 'authorization_code');
    }

    public function testAddingStorageWithValidKeyOnlySetsThatKey()
    {
        $server = new Server();
        $server->addStorage($this->getMock('OAuth2\Storage\Memory'), 'access_token');

        $reflection = new \ReflectionClass($server);
        $prop = $reflection->getProperty('storages');
        $prop->setAccessible(true);

        $storages = $prop->getValue($server); // get the private "storages" property

        $this->assertEquals(1, count($storages));
        $this->assertTrue(isset($storages['access_token']));
        $this->assertFalse(isset($storages['authorization_code']));
    }

    public function testAddingResponseType()
    {
        $storage = $this->getMock('OAuth2\Storage\Memory');
        $storage
          ->expects($this->any())
          ->method('getClientDetails')
          ->will($this->returnValue(array('client_id' => 'some_client')));
        $storage
          ->expects($this->any())
          ->method('checkRestrictedGrantType')
          ->will($this->returnValue(true));

        // add with the "code" key explicitly set
        $codeType = new AuthorizationCode($storage);
        $server = new Server();
        $server->addStorage($storage);
        $server->addResponseType($codeType);
        $request = new Request(array(
            'response_type' => 'code',
            'client_id' => 'some_client',
            'redirect_uri' => 'http://example.com',
            'state' => 'xyx',
        ));
        $server->handleAuthorizeRequest($request, $response = new Response(), true);

        // the response is successful
        $this->assertEquals($response->getStatusCode(), 302);
        $parts = parse_url($response->getHttpHeader('Location'));
        parse_str($parts['query'], $query);
        $this->assertTrue(isset($query['code']));
        $this->assertFalse(isset($query['error']));

        // add with the "code" key not set
        $codeType = new AuthorizationCode($storage);
        $server = new Server(array($storage), array(), array(), array($codeType));
        $request = new Request(array(
            'response_type' => 'code',
            'client_id' => 'some_client',
            'redirect_uri' => 'http://example.com',
            'state' => 'xyx',
        ));
        $server->handleAuthorizeRequest($request, $response = new Response(), true);

        // the response is successful
        $this->assertEquals($response->getStatusCode(), 302);
        $parts = parse_url($response->getHttpHeader('Location'));
        parse_str($parts['query'], $query);
        $this->assertTrue(isset($query['code']));
        $this->assertFalse(isset($query['error']));
    }

    public function testCustomClientAssertionType()
    {
        $request = TestRequest::createPost(array(
            'grant_type' => 'authorization_code',
            'client_id' =>'Test Client ID',
            'code' => 'testcode',
        ));
        // verify the mock clientAssertionType was called as expected
        $clientAssertionType = $this->getMock('OAuth2\ClientAssertionType\ClientAssertionTypeInterface', array('validateRequest', 'getClientId'));
        $clientAssertionType
            ->expects($this->once())
            ->method('validateRequest')
            ->will($this->returnValue(true));
        $clientAssertionType
            ->expects($this->once())
            ->method('getClientId')
            ->will($this->returnValue('Test Client ID'));

        // create mock storage
        $storage = Bootstrap::getInstance()->getMemoryStorage();
        $server = new Server(array($storage), array(), array(), array(), null, null, $clientAssertionType);
        $server->handleTokenRequest($request, $response = new Response());
    }

    public function testHttpBasicConfig()
    {
        // create mock storage
        $storage = Bootstrap::getInstance()->getMemoryStorage();
        $server = new Server(array($storage), array('allow_credentials_in_request_body' => false));
        $server->getTokenController();
        $httpBasic = $server->getClientAssertionType();

        $reflection = new \ReflectionClass($httpBasic);
        $prop = $reflection->getProperty('config');
        $prop->setAccessible(true);

        $config = $prop->getValue($httpBasic); // get the private "storages" property
        $this->assertEquals($config['allow_credentials_in_request_body'], false);
    }

    /**
     * @expectedException InvalidArgumentException OAuth2\ResponseType\AuthorizationCodeInterface
     **/
    public function testAddingUnknownResponseTypeThrowsException()
    {
        $server = new Server();
        $server->addResponseType($this->getMock('OAuth2\ResponseType\ResponseTypeInterface'));
    }

}
