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

    public function provideStorage()
    {
        $this->removeSqliteDb(); // remove db to be safe
        $this->createSqliteDb();

        $sqlite = new OAuth2_Storage_Pdo(array(
            'dsn' => sprintf('sqlite://%s', $this->getSqliteDir()),
        ));

        // will add multiple storage types later
        return array(
            array($sqlite),
        );
    }

    private function createSqliteDb()
    {
        $db = new PDO(sprintf('sqlite://%s', $this->getSqliteDir()));
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $db->exec('CREATE TABLE oauth_clients (client_id TEXT, client_secret TEXT, redirect_uri TEXT)');
        $db->exec('CREATE TABLE oauth_access_tokens (access_token TEXT, client_id TEXT, user_id TEXT, expires TIMESTAMP, scope TEXT)');

        // test data
        $db->exec('INSERT INTO oauth_clients (client_id, client_secret) VALUES ("oauth_test_client", "testpass")');
        $db->exec('INSERT INTO oauth_access_tokens (access_token, client_id) VALUES ("testtoken", "Some Client")');
    }

    private function removeSqliteDb()
    {
        if (file_exists($this->getSqliteDir())) {
            unlink($this->getSqliteDir());
        }
    }

    private function getSqliteDir()
    {
        return dirname(__FILE__).'/../../config/test.sqlite';
    }
}