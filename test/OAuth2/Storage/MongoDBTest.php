<?php

namespace OAuth2\Storage;

/**
 * Description of MongoDBTest
 *
 * @author Roman Shuplov  <astronin@gmail.com>
 */
class MongoDBTest extends BaseTest
{
    
    public function __construct()
    {
        $mongodb = Bootstrap::getInstance()->getMongoDB();
    }
    
    public function testSetClientDetails()
    {
        $db = new \OAuth2\Storage\MongoDB('mongodb://localhost:27017/oauth2_server_php');
        
// comment with Bootstrap::getInstance()->getMongoDB();
//        $db->setClientDetails('oauth_test_client', 'testpass', 'redirect_uri', [], 'map green', 'oauth_test_user_id');
        
        $this->assertFalse($db->checkClientCredentials('oauth_test_client'));
        $this->assertTrue($db->checkClientCredentials('oauth_test_client', 'testpass'));
        $this->assertFalse($db->checkClientCredentials('oauth_test_client', 'testpass!!!!'));
        
        $db->setClientDetails('oauth_test_client', 'testpass!!!', 'redirect_uri', [], 'map green', 'oauth_test_user_id');
        $this->assertFalse($db->checkClientCredentials('oauth_test_client', 'testpass'));
        
        $db->unsetClientDetails('oauth_test_client');
        $this->assertFalse($db->checkClientCredentials('oauth_test_client', 'testpass'));
        
        $db->setClientDetails('oauth_test_client', 'testpass', 'redirect_uri', [], 'map green', 'oauth_test_user_id');
        $this->assertTrue($db->checkClientCredentials('oauth_test_client', 'testpass'));
    }
    
    public function testConnection()
    {
        $db = new \OAuth2\Storage\MongoDB('mongodb://localhost:27017/oauth2_server_php');
        $this->assertNotFalse($db->getClientDetails('oauth_test_client'));
        $db = new \OAuth2\Storage\MongoDB(['host' => 'localhost', 'port' => '27017', 'database' => 'oauth2_server_php']);
        $this->assertNotFalse($db->getClientDetails('oauth_test_client'));
    }

    public function testIsPublicClient()
    {
        $db = new \OAuth2\Storage\MongoDB('mongodb://localhost:27017/oauth2_server_php');
        
        $res = $db->isPublicClient('oauth_test_client');
        $this->assertFalse($res);
    }
    
    public function testAccessToken()
    {
        $db = new \OAuth2\Storage\MongoDB('mongodb://localhost:27017/oauth2_server_php');
        
        $this->assertNotFalse($db->getAccessToken('testtoken'));
        $db->setAccessToken('testtoken', 'Some Client!!!', 'oauth_test_user_id', 1);
        $this->assertEquals($db->getAccessToken('testtoken')['client_id'], 'Some Client!!!');
        $db->unsetAccessToken('testtoken');
        $this->assertFalse($db->getAccessToken('testtoken'));
        $db->setAccessToken('testtoken', 'Some Client', 'oauth_test_user_id', 2);
        $this->assertNotFalse($db->getAccessToken('testtoken'));
        
    }
    
    public function testAuthorizationCode()
    {
        $db = new \OAuth2\Storage\MongoDB('mongodb://localhost:27017/oauth2_server_php');
        
        $this->assertNotFalse($db->getAuthorizationCode('testcode'));
        $db->setAuthorizationCode('testcode', 'Some Client!!!', 'oauth_test_user_id', 'http://example.com', 0);
        $this->assertEquals($db->getAuthorizationCode('testcode')['client_id'], 'Some Client!!!');
        $db->expireAuthorizationCode('testcode');
        $this->assertFalse($db->getAuthorizationCode('testcode'));
        $db->setAuthorizationCode('testcode', 'Some Client', 'oauth_test_user_id', 'http://example.com', 23442);
        $this->assertNotFalse($db->getAuthorizationCode('testcode'));
    }
    
    public function testRefreshToken()
    {
        $db = new \OAuth2\Storage\MongoDB('mongodb://localhost:27017/oauth2_server_php');
        
        $this->assertNotFalse($db->getRefreshToken('testrefreshtoken'));
        $db->setRefreshToken('testrefreshtoken', 'Some Client!!!', 'oauth_test_user_id', 0);
        $this->assertEquals($db->getRefreshToken('testrefreshtoken')['client_id'], 'Some Client!!!');
        $db->unsetRefreshToken('testrefreshtoken');
        $this->assertFalse($db->getRefreshToken('testrefreshtoken'));
        $db->setRefreshToken('testrefreshtoken', 'Some Client', 'oauth_test_user_id', 232342);
        $this->assertNotFalse($db->getRefreshToken('testrefreshtoken'));
    }
    
    public function testCheckUserCredentials()
    {
        $db = new \OAuth2\Storage\MongoDB('mongodb://localhost:27017/oauth2_server_php');
        
        $this->assertTrue($db->checkUserCredentials('testuser', 'password'));
    }
    
    public function testGetUserDetails()
    {
        $db = new \OAuth2\Storage\MongoDB('mongodb://localhost:27017/oauth2_server_php');
        $this->assertNotFalse($db->getUserDetails('testuser'));
    }
    
    public function testUser()
    {
        $db = new \OAuth2\Storage\MongoDB('mongodb://localhost:27017/oauth2_server_php');
        
        $this->assertNotFalse($db->getUser('testuser'));
        $db->setUser('testuser', 'password123123', 'First Name', 'Last Name');
        $this->assertTrue($db->checkUserCredentials('testuser', 'password123123'));
    }
 
    public function testGetClientKey()
    {
        $db = new \OAuth2\Storage\MongoDB('mongodb://localhost:27017/oauth2_server_php');
        
        $this->assertNotFalse($db->getClientKey('oauth_test_client', 'test_subject'));
    }
    
    public function testGetClientScope()
    {
        $db = new \OAuth2\Storage\MongoDB('mongodb://localhost:27017/oauth2_server_php');
        
        $this->assertStringMatchesFormat('%S', $db->getClientScope('oauth_test_client'));
        
    }
    
}
