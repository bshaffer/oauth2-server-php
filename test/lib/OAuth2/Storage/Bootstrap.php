<?php

class OAuth2_Storage_Bootstrap
{
    protected static $instance;
    private $mysql;
    private $sqlite;

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
            $pdo = new PDO(sprintf('sqlite://%s', $this->getSqliteDir()));
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->createSqliteDb($pdo);

            $this->sqlite = new OAuth2_Storage_Pdo($pdo);
        }
        return $this->sqlite;
    }

    public function getMemoryStorage()
    {
        return new OAuth2_Storage_Memory(json_decode(file_get_contents(dirname(__FILE__).'/../../../config/storage.json'), true));
    }

    public function getMysqlPdo()
    {
        if (!$this->mysql) {
            $pdo = new PDO('mysql:host=localhost;', 'root');
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->removeMysqlDb($pdo);
            $this->createMysqlDb($pdo);

            $this->mysql = new OAuth2_Storage_Pdo($pdo);
        }
        return $this->mysql;
    }

    private function createSqliteDb(PDO $pdo)
    {
        $pdo->exec('CREATE TABLE oauth_clients (client_id TEXT, client_secret TEXT, redirect_uri TEXT)');
        $pdo->exec('CREATE TABLE oauth_access_tokens (access_token TEXT, client_id TEXT, user_id TEXT, expires TIMESTAMP, scope TEXT)');
        $pdo->exec('CREATE TABLE oauth_authorization_codes (authorization_code TEXT, client_id TEXT, user_id TEXT, redirect_uri TEXT, expires TIMESTAMP, scope TEXT)');
        $pdo->exec('CREATE TABLE oauth_users (username TEXT, password TEXT, first_name TEXT, last_name TEXT)');

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

    private function createMysqlDb(PDO $pdo)
    {
        $pdo->exec('CREATE DATABASE oauth2_server_php');
        $pdo->exec('USE oauth2_server_php');
        $pdo->exec('CREATE TABLE oauth_clients (client_id TEXT, client_secret TEXT, redirect_uri TEXT)');
        $pdo->exec('CREATE TABLE oauth_access_tokens (access_token TEXT, client_id TEXT, user_id TEXT, expires DATETIME, scope TEXT)');
        $pdo->exec('CREATE TABLE oauth_authorization_codes (authorization_code TEXT, client_id TEXT, user_id TEXT, redirect_uri TEXT, expires DATETIME, scope TEXT)');
        $pdo->exec('CREATE TABLE oauth_users (username TEXT, password TEXT, first_name TEXT, last_name TEXT)');

        // test data
        $pdo->exec('INSERT INTO oauth_clients (client_id, client_secret) VALUES ("oauth_test_client", "testpass")');
        $pdo->exec('INSERT INTO oauth_access_tokens (access_token, client_id) VALUES ("testtoken", "Some Client")');
        $pdo->exec('INSERT INTO oauth_authorization_codes (authorization_code, client_id) VALUES ("testcode", "Some Client")');
        $pdo->exec('INSERT INTO oauth_users (username, password) VALUES ("testuser", "password")');
    }

    public function removeMysqlDb(PDO $pdo)
    {
        $pdo->exec('DROP DATABASE IF EXISTS oauth2_server_php');
    }

    private function getSqliteDir()
    {
        return dirname(__FILE__).'/../../../config/test.sqlite';
    }
}