<?php

namespace OAuth2\Storage;

class Bootstrap
{
    protected static $instance;
    private $mysql;
    private $sqlite;
    private $mongo;
    private $redis;
    private $configDir;

    public function __construct()
    {
        $this->configDir = __DIR__.'/../../../config';
    }

    public static function getInstance()
    {
        if (!self::$instance) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    public function getSqlitePdo()
    {
        if (!$this->sqlite) {
            $this->removeSqliteDb();
            $pdo = new \PDO(sprintf('sqlite://%s', $this->getSqliteDir()));
            $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
            $this->createSqliteDb($pdo);

            $this->sqlite = new Pdo($pdo);
        }

        return $this->sqlite;
    }

    public function getMemoryStorage()
    {
        return new Memory(json_decode(file_get_contents($this->configDir. '/storage.json'), true));
    }

    public function getRedisStorage()
    {
        if (!$this->redis) {
            if (class_exists('Predis\Client')) {
                $redis = new \Predis\Client();
                $redis->flushdb();
                $this->redis = new Redis($redis);
                $this->createRedisDb($this->redis);
            }
        }

        return $this->redis;
    }

    public function getMysqlPdo()
    {
        if (!$this->mysql) {
            $pdo = new \PDO('mysql:host=localhost;', 'root');
            $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
            $this->removeMysqlDb($pdo);
            $this->createMysqlDb($pdo);

            $this->mysql = new Pdo($pdo);
        }

        return $this->mysql;
    }

    public function getMongo()
    {
        if (!$this->mongo) {
            $skipMongo = isset($_SERVER['SKIP_MONGO_TESTS']) && $_SERVER['SKIP_MONGO_TESTS'];
            if (!$skipMongo && class_exists('MongoClient')) {
                $m = new \MongoClient();
                $db = $m->oauth2_server_php;
                $this->removeMongoDb($db);
                $this->createMongoDb($db);

                $this->mongo = new Mongo($db);
            }
        }

        return $this->mongo;
    }

    private function createSqliteDb(\PDO $pdo)
    {
        $this->runPdoSql($pdo);
    }

    private function removeSqliteDb()
    {
        if (file_exists($this->getSqliteDir())) {
            unlink($this->getSqliteDir());
        }
    }

    private function createMysqlDb(\PDO $pdo)
    {
        $pdo->exec('CREATE DATABASE oauth2_server_php');
        $pdo->exec('USE oauth2_server_php');
        $this->runPdoSql($pdo);
    }

    public function runPdoSql(\PDO $pdo)
    {
        $pdo->exec('CREATE TABLE oauth_clients (client_id TEXT, client_secret TEXT, redirect_uri TEXT, grant_types TEXT, user_id TEXT, scope TEXT, default_scope TEXT)');
        $pdo->exec('CREATE TABLE oauth_access_tokens (access_token TEXT, client_id TEXT, user_id TEXT, expires DATETIME, scope TEXT)');
        $pdo->exec('CREATE TABLE oauth_authorization_codes (authorization_code TEXT, client_id TEXT, user_id TEXT, redirect_uri TEXT, expires DATETIME, scope TEXT)');
        $pdo->exec('CREATE TABLE oauth_users (username TEXT, password TEXT, first_name TEXT, last_name TEXT, scope TEXT)');
        $pdo->exec('CREATE TABLE oauth_refresh_tokens (refresh_token TEXT, client_id TEXT, user_id TEXT, expires DATETIME, scope TEXT)');
        $pdo->exec('CREATE TABLE oauth_scopes (scope TEXT, is_default BOOLEAN)');
        $pdo->exec('CREATE TABLE oauth_public_keys (client_id TEXT, public_key TEXT, private_key TEXT, encryption_algorithm VARCHAR(100) DEFAULT "RS256")');

        // set up scopes
        foreach (explode(' ', 'supportedscope1 supportedscope2 supportedscope3 supportedscope4 clientscope1 clientscope2 clientscope3') as $supportedScope) {
            $pdo->exec(sprintf('INSERT INTO oauth_scopes (scope) VALUES ("%s")', $supportedScope));
        }

        foreach (array('defaultscope1', 'defaultscope2') as $defaultScope) {
            $pdo->exec(sprintf('INSERT INTO oauth_scopes (scope, is_default) VALUES ("%s", 1)', $defaultScope));
        }

        // set up clients
        $pdo->exec('INSERT INTO oauth_clients (client_id, client_secret, scope) VALUES ("Test Client ID", "TestSecret", "clientscope1 clientscope2")');
        $pdo->exec('INSERT INTO oauth_clients (client_id, client_secret, scope) VALUES ("Test Client ID 2", "TestSecret", "clientscope1 clientscope2 clientscope3")');
        $pdo->exec('INSERT INTO oauth_clients (client_id, client_secret, scope) VALUES ("Test Default Scope Client ID", "TestSecret", "clientscope1 clientscope2")');
        $pdo->exec('INSERT INTO oauth_clients (client_id, client_secret, grant_types) VALUES ("oauth_test_client", "testpass", "implicit password")');

        // set up misc
        $pdo->exec('INSERT INTO oauth_access_tokens (access_token, client_id) VALUES ("testtoken", "Some Client")');
        $pdo->exec('INSERT INTO oauth_authorization_codes (authorization_code, client_id) VALUES ("testcode", "Some Client")');
        $pdo->exec('INSERT INTO oauth_users (username, password) VALUES ("testuser", "password")');
        $pdo->exec('INSERT INTO oauth_public_keys (client_id, public_key, private_key, encryption_algorithm) VALUES ("ClientID_One", "client_1_public", "client_1_private", "RS256")');
        $pdo->exec('INSERT INTO oauth_public_keys (client_id, public_key, private_key, encryption_algorithm) VALUES ("ClientID_Two", "client_2_public", "client_2_private", "RS256")');
        $pdo->exec(sprintf('INSERT INTO oauth_public_keys (client_id, public_key, private_key, encryption_algorithm) VALUES (NULL, "%s", "%s", "RS256")', file_get_contents($this->configDir.'/keys/id_rsa.pub'), file_get_contents($this->configDir.'/keys/id_rsa')));
    }

    public function removeMysqlDb(\PDO $pdo)
    {
        $pdo->exec('DROP DATABASE IF EXISTS oauth2_server_php');
    }

    public function getSqliteDir()
    {
        return $this->configDir. '/test.sqlite';
    }

    public function getConfigDir()
    {
        return $this->configDir;
    }

    private function createMongoDb(\MongoDB $db)
    {
        $db->oauth_clients->insert(array('client_id' => "oauth_test_client", 'client_secret' => "testpass", 'redirect_uri' => "http://example.com", 'grant_types' => 'implicit password'));
        $db->oauth_access_tokens->insert(array('access_token' => "testtoken", 'client_id' => "Some Client"));
        $db->oauth_authorization_codes->insert(array('authorization_code' => "testcode", 'client_id' => "Some Client"));
        $db->oauth_users->insert(array('username' => "testuser", 'password' => "password"));
    }

    private function createRedisDb(Redis $storage)
    {
        $storage->setClientDetails("oauth_test_client", "testpass", "http://example.com", 'implicit password');
        $storage->setAccessToken("testtoken", "Some Client", '', time() + 1000);
        $storage->setAuthorizationCode("testcode", "Some Client", '', '', time() + 1000);
        $storage->setUser("testuser", "password");

        $storage->setScope('supportedscope1 supportedscope2 supportedscope3 supportedscope4');
        $storage->setScope('defaultscope1 defaultscope2', null, 'default');

        $storage->setScope('clientscope1 clientscope2', 'Test Client ID');
        $storage->setScope('clientscope1 clientscope2', 'Test Client ID', 'default');

        $storage->setScope('clientscope1 clientscope2 clientscope3', 'Test Client ID 2');
        $storage->setScope('clientscope1 clientscope2', 'Test Client ID 2', 'default');

        $storage->setScope('clientscope1 clientscope2', 'Test Default Scope Client ID');
        $storage->setScope('clientscope1 clientscope2', 'Test Default Scope Client ID', 'default');

        $storage->setScope('clientscope1 clientscope2 clientscope3', 'Test Default Scope Client ID 2');
        $storage->setScope('clientscope3', 'Test Default Scope Client ID 2', 'default');
    }

    public function removeMongoDb(\MongoDB $db)
    {
        $db->drop();
    }
}
