<?php

namespace OAuth2;

use OAuth2\Storage\ClientCredentialsInterface;
use OAuth2\Storage\ClientInterface;
use OAuth2\Storage\AccessTokenInterface;
use OAuth2\Storage\RefreshTokenInterface;
use OAuth2\Storage\AuthorizationCodeInterface;
use OAuth2\Storage\Bootstrap;

class StorageTest extends \PHPUnit_Framework_TestCase
{
    /** @dataProvider provideStorage */
    public function testCheckClientCredentials(ClientCredentialsInterface $storage = null)
    {
        if (is_null($storage)) {
            $this->markTestSkipped('Unable to load class Mongo_Client');
            return;
        }
        // nonexistant client_id
        $pass = $storage->checkClientCredentials('fakeclient', 'testpass');
        $this->assertFalse($pass);

        // invalid password
        $pass = $storage->checkClientCredentials('oauth_test_client', 'invalidcredentials');
        $this->assertFalse($pass);

        // valid credentials
        $pass = $storage->checkClientCredentials('oauth_test_client', 'testpass');
        $this->assertTrue($pass);
    }

    /** @dataProvider provideStorage */
    public function testClientScopeExists(ClientInterface $storage = null)
    {
        if (is_null($storage)) {
            $this->markTestSkipped('Unable to load class Mongo_Client');
            return;
        }

        if (!$storage instanceof \OAuth2\Storage\ScopeInterface) {
            $this->markTestSkipped('Skipping incompatible storage');
            return;
        }

        //Test getting scopes with a client_id
        $scopeUtil = new Scope($storage);
        $this->assertTrue($scopeUtil->scopeExists('clientscope1 clientscope2', 'Test Client ID'));
        $this->assertFalse($scopeUtil->scopeExists('clientscope1 clientscope2 clientscope3', 'Test Client ID'));
        $this->assertTrue($scopeUtil->scopeExists('clientscope3', 'Test Client ID 2'));
    }

    /** @dataProvider provideStorage */
    public function testGetDefaultClientScope(ClientInterface $storage = null)
    {
        if (is_null($storage)) {
            $this->markTestSkipped('Unable to load class Mongo_Client');
            return;
        }

        if (!$storage instanceof \OAuth2\Storage\ScopeInterface) {
            $this->markTestSkipped('Skipping incompatible storage');
            return;
        }

        //Test getting scopes with a client_id
        $scopeUtil = new Scope($storage);
        $this->assertEquals($scopeUtil->getDefaultScope('Test Default Scope Client ID'), 'clientscope1 clientscope2');
        $this->assertEquals($scopeUtil->getDefaultScope('Test Default Scope Client ID 2'), 'clientscope3');
    }

    /** @dataProvider provideStorage */
    public function testGetClientDetails(ClientInterface $storage = null)
    {
        if (is_null($storage)) {
            $this->markTestSkipped('Unable to load class Mongo_Client');
            return;
        }
        // nonexistant client_id
        $details = $storage->getClientDetails('fakeclient');
        $this->assertFalse($details);

        // valid client_id
        $details = $storage->getClientDetails('oauth_test_client');
        $this->assertNotNull($details);
        $this->assertArrayHasKey('client_id', $details);
        $this->assertArrayHasKey('client_secret', $details);
        $this->assertArrayHasKey('redirect_uri', $details);
    }

    /** @dataProvider provideStorage */
    public function testCheckRestrictedGrantType(ClientInterface $storage = null)
    {
        if (is_null($storage)) {
            $this->markTestSkipped('Unable to load class Mongo_Client');
            return;
        }

        // Check invalid
        $pass = $storage->checkRestrictedGrantType('oauth_test_client', 'authorization_code');
        $this->assertFalse($pass);

        // Check valid
        $pass = $storage->checkRestrictedGrantType('oauth_test_client', 'implicit');
        $this->assertTrue($pass);
    }

    /** @dataProvider provideStorage */
    public function testGetAccessToken(ClientInterface $storage = null)
    {
        if (is_null($storage)) {
            $this->markTestSkipped('Unable to load class Mongo_Client');
            return;
        }
        // nonexistant client_id
        $details = $storage->getAccessToken('faketoken');
        $this->assertFalse($details);

        // valid client_id
        $details = $storage->getAccessToken('testtoken');
        $this->assertNotNull($details);
    }

    /** @dataProvider provideStorage */
    public function testSetAccessToken(AccessTokenInterface $storage = null)
    {
        if (is_null($storage)) {
            $this->markTestSkipped('Unable to load class Mongo_Client');
            return;
        }
        // assert token we are about to add does not exist
        $token = $storage->getAccessToken('newtoken');
        $this->assertFalse($token);

        // add new token
        $expires = time() + 20;
        $success = $storage->setAccessToken('newtoken', 'client ID', 'SOMEUSERID', $expires);
        $this->assertTrue($success);

        $token = $storage->getAccessToken('newtoken');
        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
        $this->assertArrayHasKey('client_id', $token);
        $this->assertArrayHasKey('user_id', $token);
        $this->assertArrayHasKey('expires', $token);
        $this->assertEquals($token['access_token'], 'newtoken');
        $this->assertEquals($token['client_id'], 'client ID');
        $this->assertEquals($token['user_id'], 'SOMEUSERID');
        $this->assertEquals($token['expires'], $expires);

        // change existing token
        $expires = time() + 42;
        $success = $storage->setAccessToken('newtoken', 'client ID2', 'SOMEOTHERID', $expires);
        $this->assertTrue($success);

        $token = $storage->getAccessToken('newtoken');
        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
        $this->assertArrayHasKey('client_id', $token);
        $this->assertArrayHasKey('user_id', $token);
        $this->assertArrayHasKey('expires', $token);
        $this->assertEquals($token['access_token'], 'newtoken');
        $this->assertEquals($token['client_id'], 'client ID2');
        $this->assertEquals($token['user_id'], 'SOMEOTHERID');
        $this->assertEquals($token['expires'], $expires);
    }

    /** @dataProvider provideStorage */
    public function testSetRefreshToken(RefreshTokenInterface $storage = null)
    {
        if (is_null($storage)) {
            $this->markTestSkipped('Unable to load class Mongo_Client');
            return;
        }
        // assert token we are about to add does not exist
        $token = $storage->getRefreshToken('refreshtoken');
        $this->assertFalse($token);

        // add new token
        $expires = time() + 20;
        $success = $storage->setRefreshToken('refreshtoken', 'client ID', 'SOMEUSERID', $expires);
        $this->assertTrue($success);

        $token = $storage->getRefreshToken('refreshtoken');
        $this->assertNotNull($token);
        $this->assertArrayHasKey('refresh_token', $token);
        $this->assertArrayHasKey('client_id', $token);
        $this->assertArrayHasKey('user_id', $token);
        $this->assertArrayHasKey('expires', $token);
        $this->assertEquals($token['refresh_token'], 'refreshtoken');
        $this->assertEquals($token['client_id'], 'client ID');
        $this->assertEquals($token['user_id'], 'SOMEUSERID');
        $this->assertEquals($token['expires'], $expires);
    }

    /** @dataProvider provideStorage */
    public function testGetAuthorizationCode(AuthorizationCodeInterface $storage = null)
    {
        if (is_null($storage)) {
            $this->markTestSkipped('Unable to load class Mongo_Client');
            return;
        }
        // nonexistant client_id
        $details = $storage->getAuthorizationCode('faketoken');
        $this->assertFalse($details);

        // valid client_id
        $details = $storage->getAuthorizationCode('testtoken');
        $this->assertNotNull($details);
    }

    /** @dataProvider provideStorage */
    public function testSetAuthorizationCode(AuthorizationCodeInterface $storage = null)
    {
        if (is_null($storage)) {
            $this->markTestSkipped('Unable to load class Mongo_Client');
            return;
        }
        // assert code we are about to add does not exist
        $code = $storage->getAuthorizationCode('newcode');
        $this->assertFalse($code);

        // add new code
        $expires = time() + 20;
        $success = $storage->setAuthorizationCode('newcode', 'client ID', 'SOMEUSERID', 'http://example.com', $expires);
        $this->assertTrue($success);

        $code = $storage->getAuthorizationCode('newcode');
        $this->assertNotNull($code);
        $this->assertArrayHasKey('authorization_code', $code);
        $this->assertArrayHasKey('client_id', $code);
        $this->assertArrayHasKey('user_id', $code);
        $this->assertArrayHasKey('redirect_uri', $code);
        $this->assertArrayHasKey('expires', $code);
        $this->assertEquals($code['authorization_code'], 'newcode');
        $this->assertEquals($code['client_id'], 'client ID');
        $this->assertEquals($code['user_id'], 'SOMEUSERID');
        $this->assertEquals($code['redirect_uri'], 'http://example.com');
        $this->assertEquals($code['expires'], $expires);

        // change existing code
        $expires = time() + 42;
        $success = $storage->setAuthorizationCode('newcode', 'client ID2', 'SOMEOTHERID', 'http://example.org', $expires);
        $this->assertTrue($success);

        $code = $storage->getAuthorizationCode('newcode');
        $this->assertNotNull($code);
        $this->assertArrayHasKey('authorization_code', $code);
        $this->assertArrayHasKey('client_id', $code);
        $this->assertArrayHasKey('user_id', $code);
        $this->assertArrayHasKey('redirect_uri', $code);
        $this->assertArrayHasKey('expires', $code);
        $this->assertEquals($code['authorization_code'], 'newcode');
        $this->assertEquals($code['client_id'], 'client ID2');
        $this->assertEquals($code['user_id'], 'SOMEOTHERID');
        $this->assertEquals($code['redirect_uri'], 'http://example.org');
        $this->assertEquals($code['expires'], $expires);
    }

    /** @dataProvider provideStorage */
    public function testCheckUserCredentials($storage)
    {
        if (is_null($storage)) {
            $this->markTestSkipped('Unable to load class Mongo_Client');
            return;
        }
        // create a new user for testing
        $success = $storage->setUser('testusername', 'testpass', 'Test', 'User');
        $this->assertTrue($success);

        // correct credentials
        $this->assertTrue($storage->checkUserCredentials('testusername', 'testpass'));
        // invalid password
        $this->assertFalse($storage->checkUserCredentials('testusername', 'fakepass'));
        // invalid username
        $this->assertFalse($storage->checkUserCredentials('fakeusername', 'testpass'));

        // invalid username
        $this->assertFalse($storage->getUserDetails('fakeusername'));

        // ensure all properties are set
        $user = $storage->getUserDetails('testusername');
        $this->assertTrue($user !== false);
        $this->assertArrayHasKey('user_id', $user);
        $this->assertArrayHasKey('first_name', $user);
        $this->assertArrayHasKey('last_name', $user);
        $this->assertEquals($user['user_id'], 'testusername');
        $this->assertEquals($user['first_name'], 'Test');
        $this->assertEquals($user['last_name'], 'User');
    }

    public function provideStorage()
    {
        $memory = Bootstrap::getInstance()->getMemoryStorage();
        $mysql = Bootstrap::getInstance()->getMysqlPdo();
        $sqlite = Bootstrap::getInstance()->getSqlitePdo();
        $mongo = Bootstrap::getInstance()->getMongo();
        $redis = Bootstrap::getInstance()->getRedisStorage();

        // will add multiple storage types later
        return array(
            array($memory),
            array($sqlite),
            array($mysql),
            array($mongo),
            array($redis)
        );
    }
}
