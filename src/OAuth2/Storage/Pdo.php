<?php

/**
*
*/
class OAuth2_Storage_Pdo implements OAuth2_Storage_AuthorizationCodeInterface,
    OAuth2_Storage_AccessTokenInterface, OAuth2_Storage_ClientCredentialsInterface,
    OAuth2_Storage_UserCredentialsInterface
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
            'code_table_name' => 'oauth_authorization_codes',
            'user_table_name' => 'oauth_users',
            'user_id_as_int' => false,
            'username_field' => 'username',
    		'password_field' => 'password',
        ), $config);
    }

    /* ClientCredentialsInterface */
    public function checkClientCredentials($client_id, $client_secret = null)
    {
        $stmt = $this->db->prepare('SELECT * FROM ' . $this->config['client_table_name'] . ' WHERE client_id = :client_id');
    	$stmt->bindParam(':client_id', $client_id, PDO::PARAM_STR);
        $stmt->execute();
        $result = $stmt->fetch();

        // make this extensible
        return $result['client_secret'] == $client_secret;
    }

    public function getClientDetails($client_id)
    {
        $stmt = $this->db->prepare('SELECT * FROM ' . $this->config['client_table_name'] . ' WHERE client_id = :client_id');
    	$stmt->bindParam(':client_id', $client_id, PDO::PARAM_STR);
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
        $stmt = $this->db->prepare('SELECT * FROM ' . $this->config['token_table_name'] . ' WHERE access_token = :access_token');
    	$stmt->bindParam(':access_token', $access_token, PDO::PARAM_STR);

        $token = $stmt->execute();
        if ($token = $stmt->fetch()) {
            // convert date string back to timestamp
            $token['expires'] = strtotime($token['expires']);
        }

        return $token;
    }

    public function setAccessToken($access_token, $client_id, $user_id, $expires, $scope = null)
    {
        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);

        // if it exists, update it.
        if ($this->getAccessToken($access_token)) {
            $stmt = $this->db->prepare('UPDATE ' . $this->config['token_table_name'] . ' SET client_id=:client_id, expires=:expires, user_id=:user_id, scope=:scope WHERE access_token=:access_token');
        } else {
            $stmt = $this->db->prepare('INSERT INTO ' . $this->config['token_table_name'] . ' (access_token, client_id, expires, user_id, scope) VALUES (:access_token, :client_id, :expires, :user_id, :scope)');
        }

    	$stmt->bindParam(':access_token', $access_token, PDO::PARAM_STR);
		$stmt->bindParam(':client_id', $client_id, PDO::PARAM_STR);
		$stmt->bindParam(':user_id', $user_id, $this->config['user_id_as_int'] ? PDO::PARAM_INT : PDO::PARAM_STR);
		$stmt->bindParam(':expires', $expires, PDO::PARAM_STR);
		$stmt->bindParam(':scope', $scope, PDO::PARAM_STR);

        return $stmt->execute();
    }

    /* AuthorizationCodeInterface */
    public function getAuthorizationCode($code)
    {
        $stmt = $this->db->prepare('SELECT * FROM ' . $this->config['code_table_name'] . ' WHERE authorization_code = :authorization_code');
    	$stmt->bindParam(':authorization_code', $code, PDO::PARAM_STR);
        $stmt->execute();

        if ($code = $stmt->fetch()) {
            // convert date string back to timestamp
            $code['expires'] = strtotime($code['expires']);
        }

        return $code;
    }

    public function setAuthorizationCode($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null)
    {
        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);

        // if it exists, update it.
        if ($this->getAuthorizationCode($code)) {
            $stmt = $this->db->prepare('UPDATE ' . $this->config['code_table_name'] . ' SET client_id=:client_id, user_id=:user_id, redirect_uri=:redirect_uri, expires=:expires, scope=:scope WHERE authorization_code=:code');
        } else {
            $stmt = $this->db->prepare('INSERT INTO ' . $this->config['code_table_name'] . ' (authorization_code, client_id, user_id, redirect_uri, expires, scope) VALUES (:code, :client_id, :user_id, :redirect_uri, :expires, :scope)');
        }

    	$stmt->bindParam(':code', $code, PDO::PARAM_STR);
		$stmt->bindParam(':client_id', $client_id, PDO::PARAM_STR);
		$stmt->bindParam(':user_id', $user_id, $this->config['user_id_as_int'] ? PDO::PARAM_INT : PDO::PARAM_STR);
		$stmt->bindParam(':redirect_uri', $redirect_uri, PDO::PARAM_STR);
		$stmt->bindParam(':expires', $expires, PDO::PARAM_STR);
		$stmt->bindParam(':scope', $scope, PDO::PARAM_STR);

        return $stmt->execute();
    }

    /* UserCredentialsInterface */
    public function checkUserCredentials($username, $password)
    {
        if ($user = $this->getUser($username)) {
            return $this->checkPassword($user, $password);
        }
        return false;
    }

    // plaintext passwords are bad!  Override this for your application
    protected function checkPassword($user, $password)
    {
        return $user['password'] == $password;
    }

    public function getUser($username)
    {
        $stmt = $this->db->prepare('SELECT * FROM ' . $this->config['user_table_name'] . ' WHERE ' . $this->config['username_field'] . '=:username');
    	$stmt->bindParam(':username', $username);
        $stmt->execute();
        return $stmt->fetch();
    }

    public function setUser($username, $password, $firstName = null, $lastName = null)
    {
        // if it exists, update it.
        if ($this->getUser($username)) {
            $stmt = $this->db->prepare('UPDATE ' . $this->config['user_table_name'] . ' SET ' . $this->config['username_field'] . '=:username, ' . $this->config['password_field'] . '=:password, first_name=:firstName, last_name=:lastName WHERE username=:username');
        } else {
            $stmt = $this->db->prepare('INSERT INTO ' . $this->config['user_table_name'] . ' (' . $this->config['username_field'] . ', ' . $this->config['password_field'] . ', first_name, last_name) VALUES (:username, :password, :firstName, :lastName)');
        }

    	$stmt->bindParam(':username', $username);
		$stmt->bindParam(':password', $password);
		$stmt->bindParam(':firstName', $firstName);
		$stmt->bindParam(':lastName', $lastName);

        return $stmt->execute();
    }
}