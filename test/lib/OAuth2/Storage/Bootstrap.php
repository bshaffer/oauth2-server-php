<?php

namespace OAuth2\Storage;

class Bootstrap
{
    protected static $instance;
    private $mysql;
    private $sqlite;
    private $postgres;
    private $mongo;
    private $redis;
    private $cassandra;
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

    public function getPostgresPdo()
    {
        if (!$this->postgres) {
            if (in_array('pgsql', \PDO::getAvailableDrivers())) {
                $this->removePostgresDb();
                $this->createPostgresDb();
                if ($pdo = $this->getPostgresDriver()) {
                    $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
                    $this->populatePostgresDb($pdo);
                    $this->postgres = new Pdo($pdo);
                } else {
                    $this->postgres = new NullStorage('Postgres', 'Unable to connect to postgres on localhost with user "postgres"');
                }
            } else {
                $this->postgres = new NullStorage('Postgres', 'Missing postgres PDO extension.');
            }
        }

        return $this->postgres;
    }

    public function getPostgresDriver()
    {
        try {
            $pdo = new \PDO('pgsql:host=localhost;dbname=oauth2_server_php', 'postgres');

            return $pdo;
        } catch (\PDOException $e) {
            exit($e->getMessage());
        }
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
                if ($this->testRedisConnection($redis)) {
                    $redis->flushdb();
                    $this->redis = new Redis($redis);
                    $this->createRedisDb($this->redis);
                } else {
                    $this->redis = new NullStorage('Redis', 'Unable to connect to redis server on port 6379');
                }
            } else {
                $this->redis = new NullStorage('Redis', 'Missing redis library. Please run "composer.phar require predis/predis:dev-master"');
            }
        }

        return $this->redis;
    }

    private function testRedisConnection(\Predis\Client $redis)
    {
        try {
            $redis->connect();
        } catch (\Predis\CommunicationException $exception) {
            // we were unable to connect to the redis server
            return false;
        }

        return true;
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
                $mongo = new \MongoClient('mongodb://localhost:27017', array('connect' => false));
                if ($this->testMongoConnection($mongo)) {
                    $db = $mongo->oauth2_server_php;
                    $this->removeMongoDb($db);
                    $this->createMongoDb($db);

                    $this->mongo = new Mongo($db);
                } else {
                    $this->mongo = new NullStorage('Mongo', 'Unable to connect to mongo server on "localhost:27017"');
                }
            } else {
                $this->mongo = new NullStorage('Mongo', 'Missing mongo php extension. Please install mongo.so');
            }
        }

        return $this->mongo;
    }

    private function testMongoConnection(\MongoClient $mongo)
    {
        try {
            $mongo->connect();
        } catch (\MongoConnectionException $e) {
            return false;
        }

        return true;
    }

    public function getCassandraStorage()
    {
        if (!$this->cassandra) {
            if (class_exists('phpcassa\ColumnFamily')) {
                $cassandra = new \phpcassa\Connection\ConnectionPool('oauth2_test', array('127.0.0.1:9160'));
                if ($this->testCassandraConnection($cassandra)) {
                    $this->removeCassandraDb();
                    $this->cassandra = new Cassandra($cassandra);
                    $this->createCassandraDb($this->cassandra);
                } else {
                    $this->cassandra = new NullStorage('Cassandra', 'Unable to connect to cassandra server on "127.0.0.1:9160"');
                }
            } else {
                $this->cassandra = new NullStorage('Cassandra', 'Missing cassandra library. Please run "composer.phar require thobbs/phpcassa:dev-master"');
            }
        }

        return $this->cassandra;
    }

    private function testCassandraConnection(\phpcassa\Connection\ConnectionPool $cassandra)
    {
        try {
            new \phpcassa\SystemManager('localhost:9160');
        } catch (\Exception $e) {
            return false;
        }

        return true;
    }

    private function removeCassandraDb()
    {
        $sys = new \phpcassa\SystemManager('localhost:9160');

        try {
            $sys->drop_keyspace('oauth2_test');
        } catch (\cassandra\InvalidRequestException $e) {

        }
    }

    private function createCassandraDb(Cassandra $storage)
    {
        // create the cassandra keyspace and column family
        $sys = new \phpcassa\SystemManager('localhost:9160');

        $sys->create_keyspace('oauth2_test', array(
            "strategy_class" => \phpcassa\Schema\StrategyClass::SIMPLE_STRATEGY,
            "strategy_options" => array('replication_factor' => '1')
        ));

        $sys->create_column_family('oauth2_test', 'auth');

        // populate the data
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

        $storage->setClientKey('oauth_test_client', $this->getTestPublicKey(), 'test_subject');
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

    private function removeMysqlDb(\PDO $pdo)
    {
        $pdo->exec('DROP DATABASE IF EXISTS oauth2_server_php');
    }

    private function createPostgresDb()
    {
        `createdb -O postgres oauth2_server_php`;
    }

    private function populatePostgresDb(\PDO $pdo)
    {
        $this->runPdoSql($pdo);
    }

    private function removePostgresDb()
    {
        `dropdb oauth2_server_php`;
    }

    public function runPdoSql(\PDO $pdo)
    {
        $pdo->exec('CREATE TABLE oauth_clients (client_id TEXT, client_secret TEXT, redirect_uri TEXT, grant_types TEXT, scope TEXT, user_id TEXT, public_key TEXT)');
        $pdo->exec('CREATE TABLE oauth_access_tokens (access_token TEXT, client_id TEXT, user_id TEXT, expires TIMESTAMP, scope TEXT)');
        $pdo->exec('CREATE TABLE oauth_authorization_codes (authorization_code TEXT, client_id TEXT, user_id TEXT, redirect_uri TEXT, expires TIMESTAMP, scope TEXT, id_token TEXT)');
        $pdo->exec('CREATE TABLE oauth_users (username TEXT, password TEXT, first_name TEXT, last_name TEXT, scope TEXT, email TEXT, email_verified BOOLEAN)');
        $pdo->exec('CREATE TABLE oauth_refresh_tokens (refresh_token TEXT, client_id TEXT, user_id TEXT, expires TIMESTAMP, scope TEXT)');
        $pdo->exec('CREATE TABLE oauth_scopes (scope TEXT, is_default BOOLEAN)');
        $pdo->exec('CREATE TABLE oauth_public_keys (client_id TEXT, public_key TEXT, private_key TEXT, encryption_algorithm VARCHAR(100) DEFAULT \'RS256\')');
        $pdo->exec('CREATE TABLE oauth_jwt (client_id VARCHAR(80), subject VARCHAR(80), public_key VARCHAR(2000))');

        // set up scopes
        $sql = 'INSERT INTO oauth_scopes (scope) VALUES (?)';
        foreach (explode(' ', 'supportedscope1 supportedscope2 supportedscope3 supportedscope4 clientscope1 clientscope2 clientscope3') as $supportedScope) {
            $pdo->prepare($sql)->execute(array($supportedScope));
        }

        $sql = 'INSERT INTO oauth_scopes (scope, is_default) VALUES (?, ?)';
        foreach (array('defaultscope1', 'defaultscope2') as $defaultScope) {
            $pdo->prepare($sql)->execute(array($defaultScope, true));
        }

        // set up clients
        $sql = 'INSERT INTO oauth_clients (client_id, client_secret, scope, grant_types) VALUES (?, ?, ?, ?)';
        $pdo->prepare($sql)->execute(array('Test Client ID', 'TestSecret', 'clientscope1 clientscope2', null));
        $pdo->prepare($sql)->execute(array('Test Client ID 2', 'TestSecret', 'clientscope1 clientscope2 clientscope3', null));
        $pdo->prepare($sql)->execute(array('Test Default Scope Client ID', 'TestSecret', 'clientscope1 clientscope2', null));
        $pdo->prepare($sql)->execute(array('oauth_test_client', 'testpass', null, 'implicit password'));

        // set up misc
        $sql = 'INSERT INTO oauth_access_tokens (access_token, client_id, user_id) VALUES (?, ?, ?)';
        $pdo->prepare($sql)->execute(array('testtoken', 'Some Client', null));
        $pdo->prepare($sql)->execute(array('accesstoken-openid-connect', 'Some Client', 'testuser'));

        $sql = 'INSERT INTO oauth_authorization_codes (authorization_code, client_id) VALUES (?, ?)';
        $pdo->prepare($sql)->execute(array('testcode', 'Some Client'));

        $sql = 'INSERT INTO oauth_users (username, password, email, email_verified) VALUES (?, ?, ?, ?)';
        $pdo->prepare($sql)->execute(array('testuser', 'password', 'testuser@test.com', true));

        $sql = 'INSERT INTO oauth_public_keys (client_id, public_key, private_key, encryption_algorithm) VALUES (?, ?, ?, ?)';
        $pdo->prepare($sql)->execute(array('ClientID_One', 'client_1_public', 'client_1_private', 'RS256'));
        $pdo->prepare($sql)->execute(array('ClientID_Two', 'client_2_public', 'client_2_private', 'RS256'));

        $sql = 'INSERT INTO oauth_public_keys (client_id, public_key, private_key, encryption_algorithm) VALUES (?, ?, ?, ?)';
        $pdo->prepare($sql)->execute(array(null, $this->getTestPublicKey(), $this->getTestPrivateKey(), 'RS256'));

        $sql = 'INSERT INTO oauth_jwt (client_id, subject, public_key) VALUES (?, ?, ?)';
        $pdo->prepare($sql)->execute(array('oauth_test_client', 'test_subject', $this->getTestPublicKey()));
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
        $db->oauth_clients->insert(array(
            'client_id' => "oauth_test_client",
            'client_secret' => "testpass",
            'redirect_uri' => "http://example.com",
            'grant_types' => 'implicit password'
        ));

        $db->oauth_access_tokens->insert(array(
            'access_token' => "testtoken",
            'client_id' => "Some Client"
        ));

        $db->oauth_authorization_codes->insert(array(
            'authorization_code' => "testcode",
            'client_id' => "Some Client"
        ));

        $db->oauth_users->insert(array(
            'username' => "testuser",
            'password' => "password"
        ));

        $db->oauth_jwt->insert(array(
            'client_id' => 'oauth_test_client',
            'key'       => $this->getTestPublicKey(),
            'subject'   => 'test_subject',
        ));
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

        $storage->setClientKey('oauth_test_client', $this->getTestPublicKey(), 'test_subject');
    }

    public function removeMongoDb(\MongoDB $db)
    {
        $db->drop();
    }

    public function getTestPublicKey()
    {
        return file_get_contents(__DIR__.'/../../../config/keys/id_rsa.pub');
    }

    private function getTestPrivateKey()
    {
        return file_get_contents(__DIR__.'/../../../config/keys/id_rsa');
    }
}
