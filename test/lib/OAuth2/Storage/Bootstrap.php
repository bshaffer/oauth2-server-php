<?php

namespace OAuth2\Storage;

class Bootstrap
{
    protected static $instance;
    private $mysql;
    private $sqlite;
    private $mongo;

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
        return new Memory(json_decode(file_get_contents(dirname(__FILE__).'/../../../config/storage.json'), true));
    }

    public function getRedisStorage()
    {
        return new Redis(new MockRedisClient());
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
        $pdo->exec('CREATE TABLE oauth_clients (client_id TEXT, client_secret TEXT, redirect_uri TEXT)');
        $pdo->exec('CREATE TABLE oauth_access_tokens (access_token TEXT, client_id TEXT, user_id TEXT, expires TIMESTAMP, scope TEXT)');
        $pdo->exec('CREATE TABLE oauth_authorization_codes (authorization_code TEXT, client_id TEXT, user_id TEXT, redirect_uri TEXT, expires TIMESTAMP, scope TEXT)');
        $pdo->exec('CREATE TABLE oauth_users (username TEXT, password TEXT, first_name TEXT, last_name TEXT)');
        $pdo->exec('CREATE TABLE oauth_refresh_tokens (refresh_token TEXT, client_id TEXT, user_id TEXT, expires TIMESTAMP, scope TEXT)');

        // test data
        $pdo->exec('INSERT INTO oauth_clients (client_id, client_secret) VALUES ("oauth_test_client", "testpass")');
        $pdo->exec('INSERT INTO oauth_access_tokens (access_token, client_id) VALUES ("testtoken", "Some Client")');
        $pdo->exec('INSERT INTO oauth_authorization_codes (authorization_code, client_id) VALUES ("testcode", "Some Client")');
        $pdo->exec('INSERT INTO oauth_users (username, password) VALUES ("testuser", "password")');
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
        $pdo->exec('CREATE TABLE oauth_clients (client_id TEXT, client_secret TEXT, redirect_uri TEXT)');
        $pdo->exec('CREATE TABLE oauth_access_tokens (access_token TEXT, client_id TEXT, user_id TEXT, expires DATETIME, scope TEXT)');
        $pdo->exec('CREATE TABLE oauth_authorization_codes (authorization_code TEXT, client_id TEXT, user_id TEXT, redirect_uri TEXT, expires DATETIME, scope TEXT)');
        $pdo->exec('CREATE TABLE oauth_users (username TEXT, password TEXT, first_name TEXT, last_name TEXT)');
        $pdo->exec('CREATE TABLE oauth_refresh_tokens (refresh_token TEXT, client_id TEXT, user_id TEXT, expires DATETIME, scope TEXT)');

        // test data
        $pdo->exec('INSERT INTO oauth_clients (client_id, client_secret) VALUES ("oauth_test_client", "testpass")');
        $pdo->exec('INSERT INTO oauth_access_tokens (access_token, client_id) VALUES ("testtoken", "Some Client")');
        $pdo->exec('INSERT INTO oauth_authorization_codes (authorization_code, client_id) VALUES ("testcode", "Some Client")');
        $pdo->exec('INSERT INTO oauth_users (username, password) VALUES ("testuser", "password")');
    }

    public function removeMysqlDb(\PDO $pdo)
    {
        $pdo->exec('DROP DATABASE IF EXISTS oauth2_server_php');
    }

    private function getSqliteDir()
    {
        return dirname(__FILE__).'/../../../config/test.sqlite';
    }

    private function createMongoDb(\MongoDB $db)
    {
        $db->oauth_clients->insert(array('client_id' => "oauth_test_client", 'client_secret' => "testpass", 'redirect_uri' => "http://example.com"));
        $db->oauth_access_tokens->insert(array('access_token' => "testtoken", 'client_id' => "Some Client"));
        $db->oauth_authorization_codes->insert(array('authorization_code' => "testcode", 'client_id' => "Some Client"));
        $db->oauth_users->insert(array('username' => "testuser", 'password' => "password"));
    }

    public function removeMongoDb(\MongoDB $db)
    {
        $db->drop();
    }
}
