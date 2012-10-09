<?php

/**
*
*/
class OAuth2_Storage_Pdo implements OAuth2_Storage_AccessTokenInterface, OAuth2_Storage_ClientCredentialsInterface
{
    private $db;
    private $config;

    public function __construct($connection, $config = array())
    {
        if (!$connection instanceof PDO) {
            if (!is_array($connection)) {
                throw new InvalidArgumentException('First argument to OAuth2_Storage_Pdo must be an instance of PDO or a configuration array');
            }
            if (!isset($connection['dsn'])) {
                throw new InvalidArgumentException('configuration array must contain "dsn"');
            }
            // merge optional parameters
            $connection = array_merge(array(
                'username' => null,
                'password' => null,
            ), $connection);
            $connection = new PDO($connection['dsn'], $connection['username'], $connection['password']);
        }
        $this->db = $connection;

        // debugging
        $connection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $this->config = array_merge(array(
            'client_table_name' => 'oauth_clients',
            'token_table_name' => 'oauth_access_tokens',
        ), $config);
    }

    /* ClientCredentialsInterface */
    public function checkClientCredentials($client_id, $client_secret = null)
    {
        $stmt = $this->db->prepare(sprintf('SELECT * from %s where client_id = "%s"', $this->config['client_table_name'], $client_id));
        $stmt->execute();
        $result = $stmt->fetch();

        // make this extensible
        return $result['client_secret'] == $client_secret;
    }

    public function getClientDetails($client_id)
    {
        $stmt = $this->db->prepare(sprintf('SELECT * from %s where client_id = "%s"', $this->config['client_table_name'], $client_id));
        $stmt->execute();

        return $stmt->fetch();
    }

    public function checkRestrictedGrantType($client_id, $grant_type)
    {
        $details = $this->getClientDetails($client_id);
        if (isset($details['grant_types'])) {
            return in_array($grant_type, (array) $details['grant_types']);
        }

        // if grant_types are not defined, then none are restricted
        return true;
    }

    /* AccessTokenInterface */
    public function getAccessToken($access_token)
    {
        $stmt = $this->db->prepare(sprintf('SELECT * from %s where access_token = "%s"', $this->config['token_table_name'], $access_token));
        $stmt->execute();

        return $stmt->fetch();
    }

    public function setAccessToken($access_token, $client_id, $user_id, $expires, $scope = NULL)
    {
        // if it exists, update it.
        if ($this->getAccessToken($access_token)) {
            $stmt = $this->db->prepare(sprintf('UPDATE %s SET client_id=:client_id, expires=:expires, user_id=:user_id, scope=:scope where access_token=:access_token', $this->config['token_table_name']));
        } else {
            $stmt = $this->db->prepare(sprintf('INSERT INTO %s (client_id, expires, user_id, scope, access_token) VALUES (:client_id, :expires, :user_id, :scope, :access_token)', $this->config['token_table_name']));
        }
        return $stmt->execute(compact('access_token', 'client_id', 'user_id', 'expires', 'scope'));
    }
}