<?php

class OAuth2_Storage_PdoTest extends PHPUnit_Framework_TestCase
{
    /** @dataProvider provideStorage */
    public function testCheckClientCredentials($storage)
    {
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
    public function testGetClientDetails($storage)
    {
        // nonexistant client_id
        $details = $storage->getClientDetails('fakeclient');
        $this->assertFalse($details);

        // valid client_id
        $details = $storage->getClientDetails('oauth_test_client');
        $this->assertNotNull($details);
        $this->arrayHasKey('client_identifier', $details);
        $this->arrayHasKey('client_secret', $details);
        $this->arrayHasKey('redirect_uri', $details);
    }

    /** @dataProvider provideStorage */
    public function testGetAccessToken($storage)
    {
        // nonexistant client_id
        $details = $storage->getAccessToken('faketoken');
        $this->assertFalse($details);

        // valid client_id
        $details = $storage->getAccessToken('testtoken');
        $this->assertNotNull($details);
    }

    /** @dataProvider provideStorage */
    public function testSetAccessToken($storage)
    {
        // assert token we are about to add does not exist
        $token = $storage->getAccessToken('newtoken');
        $this->assertFalse($token);

        // add new token
        $success = $storage->setAccessToken('newtoken', 'client ID', 'SOMEUSERID', time() + 20);
        $this->assertTrue($success);

        $token = $storage->getAccessToken('newtoken');
        $this->assertNotNull($token);
        $this->arrayHasKey('access_token', $token);
        $this->arrayHasKey('client_id', $token);
        $this->arrayHasKey('user_id', $token);
        $this->assertEquals($token['user_id'], 'SOMEUSERID');

        // change existing token
        $success = $storage->setAccessToken('newtoken', 'client ID', 'SOMEOTHERID', time() + 20);
        $this->assertTrue($success);

        $token = $storage->getAccessToken('newtoken');
        $this->assertNotNull($token);
        $this->arrayHasKey('access_token', $token);
        $this->arrayHasKey('client_id', $token);
        $this->arrayHasKey('user_id', $token);
        $this->assertEquals($token['user_id'], 'SOMEOTHERID');
    }

    /** @dataProvider provideStorage */
    public function testGetAuthorizationCode($storage)
    {
        // nonexistant client_id
        $details = $storage->getAuthorizationCode('faketoken');
        $this->assertFalse($details);

        // valid client_id
        $details = $storage->getAuthorizationCode('testtoken');
        $this->assertNotNull($details);
    }

    /** @dataProvider provideStorage */
    public function testSetAuthorizationCode($storage)
    {
        // assert code we are about to add does not exist
        $code = $storage->getAuthorizationCode('newcode');
        $this->assertFalse($code);

        // add new code
        $success = $storage->setAuthorizationCode('newcode', 'client ID', 'SOMEUSERID', 'http://adobe.com', time() + 20);
        $this->assertTrue($success);

        $code = $storage->getAuthorizationCode('newcode');
        $this->assertNotNull($code);
        $this->arrayHasKey('access_token', $code);
        $this->arrayHasKey('client_id', $code);
        $this->arrayHasKey('user_id', $code);
        $this->assertEquals($code['user_id'], 'SOMEUSERID');
        $this->arrayHasKey('redirect_uri', $code);

        // change existing code
        $success = $storage->setAuthorizationCode('newcode', 'client ID', 'SOMEOTHERID', 'http://adobe.com', time() + 20);
        $this->assertTrue($success);

        $code = $storage->getAuthorizationCode('newcode');
        $this->assertNotNull($code);
        $this->arrayHasKey('access_token', $code);
        $this->arrayHasKey('client_id', $code);
        $this->arrayHasKey('user_id', $code);
        $this->assertEquals($code['user_id'], 'SOMEOTHERID');
        $this->arrayHasKey('redirect_uri', $code);
    }

    /** @dataProvider provideStorage */
    public function testCheckUserCredentials($storage)
    {
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
        $this->assertFalse($storage->getUser('fakeusername'));

        // ensure all properties are set
        $user = $storage->getUser('testusername');
        $this->assertTrue($user !== false);
        $this->assertEquals($user['username'], 'testusername');
        $this->assertEquals($user['first_name'], 'Test');
        $this->assertEquals($user['last_name'], 'User');
    }

    public function provideStorage()
    {
        $mysql = OAuth2_Storage_Bootstrap::getInstance()->getMysqlPdo();
        $sqlite = OAuth2_Storage_Bootstrap::getInstance()->getSqlitePdo();

        // will add multiple storage types later
        return array(
            array($sqlite),
            array($mysql),
        );
    }
}