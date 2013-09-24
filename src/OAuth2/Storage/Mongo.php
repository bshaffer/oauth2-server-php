<?php

namespace OAuth2\Storage;

/**
 * Simple MongoDB storage for all storage types
 *
 * NOTE: This class should never be used in production, and is
 * a stub class for example use only
 *
 * @author Julien Chaumond <chaumond@gmail.com>
 */
class Mongo implements AuthorizationCodeInterface,
    AccessTokenInterface,
    ClientCredentialsInterface,
    UserCredentialsInterface,
    RefreshTokenInterface,
    JwtBearerInterface
{
    protected $db;
    protected $config;

    public function __construct($connection, $config = array())
    {
        if ($connection instanceof \MongoDB) {
            $this->db = $connection;
        }
        else {
            if (!is_array($connection)) {
                throw new \InvalidArgumentException('First argument to OAuth2_Storage_Mongo must be an instance of MongoDB or a configuration array');
            }
            $server = sprintf('mongodb://%s:%d', $connection['host'], $connection['port']);
            $m = new \MongoClient($server);
            $this->db = $m->{$connection['database']};
        }

        // Unix timestamps might get larger than 32 bits,
        // so let's add native support for 64 bit ints.
        ini_set('mongo.native_long', 1);

        $this->config = array_merge(array(
            'client_table' => 'oauth_clients',
            'access_token_table' => 'oauth_access_tokens',
            'refresh_token_table' => 'oauth_refresh_tokens',
            'code_table' => 'oauth_authorization_codes',
            'user_table' => 'oauth_users',
            'jwt_table' => 'oauth_jwt',
        ), $config);
    }

    // Helper function to access a MongoDB collection by `type`:
    protected function collection($name)
    {
        return $this->db->{$this->config[$name]};
    }

    /* ClientCredentialsInterface */
    public function checkClientCredentials($client_id, $client_secret = null)
    {
        if ($result = $this->collection('client_table')->findOne(array('client_id' => $client_id))) {
            return $result['client_secret'] == $client_secret;
        }
        return false;
    }

    public function getClientDetails($client_id)
    {
        $result = $this->collection('client_table')->findOne(array('client_id' => $client_id));

        return is_null($result) ? false : $result;
    }

    public function checkRestrictedGrantType($client_id, $grant_type)
    {
        $details = $this->getClientDetails($client_id);
        if (isset($details['grant_types'])) {
            $grant_types = explode(' ', $details['grant_types']);

            return in_array($grant_type, $grant_types);
        }

        // if grant_types are not defined, then none are restricted
        return true;
    }

    /* AccessTokenInterface */
    public function getAccessToken($access_token)
    {
        $token = $this->collection('access_token_table')->findOne(array('access_token' => $access_token));

        return is_null($token) ? false : $token;
    }

    public function setAccessToken($access_token, $client_id, $user_id, $expires, $scope = null)
    {
        // if it exists, update it.
        if ($this->getAccessToken($access_token)) {
            $this->collection('access_token_table')->update(
                array('access_token' => $access_token),
                array('$set' => array(
                    'client_id' => $client_id,
                    'expires' => $expires,
                    'user_id' => $user_id,
                    'scope' => $scope
                ))
            );
        } else {
            $this->collection('access_token_table')->insert(
                array(
                    'access_token' => $access_token,
                    'client_id' => $client_id,
                    'expires' => $expires,
                    'user_id' => $user_id,
                    'scope' => $scope
                )
            );
        }

        return true;
    }


    /* AuthorizationCodeInterface */
    public function getAuthorizationCode($code)
    {
        $code = $this->collection('code_table')->findOne(array('authorization_code' => $code));

        return is_null($code) ? false : $code;
    }

    public function setAuthorizationCode($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null)
    {
        // if it exists, update it.
        if ($this->getAuthorizationCode($code)) {
            $this->collection('code_table')->update(
                array('authorization_code' => $code),
                array('$set' => array(
                    'client_id' => $client_id,
                    'user_id' => $user_id,
                    'redirect_uri' => $redirect_uri,
                    'expires' => $expires,
                    'scope' => $scope
                ))
            );
        } else {
            $this->collection('code_table')->insert(
                array(
                    'authorization_code' => $code,
                    'client_id' => $client_id,
                    'user_id' => $user_id,
                    'redirect_uri' => $redirect_uri,
                    'expires' => $expires,
                    'scope' => $scope
                )
            );
        }

        return true;
    }

    public function expireAuthorizationCode($code)
    {
        $this->collection('code_table')->remove(array('authorization_code' => $code));

        return true;
    }


    /* UserCredentialsInterface */
    public function checkUserCredentials($username, $password)
    {
        if ($user = $this->getUser($username)) {
            return $this->checkPassword($user, $password);
        }
        return false;
    }

    public function getUserDetails($username)
    {
        if ($user = $this->getUser($username)) {
            $user['user_id'] = $user['username'];
        }

        return $user;
    }

    /* RefreshTokenInterface */
    public function getRefreshToken($refresh_token)
    {
        $token = $this->collection('refresh_token_table')->findOne(array('refresh_token' => $refresh_token));

        return is_null($token) ? false : $token;
    }

    public function setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope = null)
    {
        $this->collection('refresh_token_table')->insert(
            array(
                'refresh_token' => $refresh_token,
                'client_id' => $client_id,
                'user_id' => $user_id,
                'expires' => $expires,
                'scope' => $scope
            )
        );

        return true;
    }

    public function unsetRefreshToken($refresh_token)
    {
        $this->collection('refresh_token_table')->remove(array('refresh_token' => $refresh_token));

        return true;
    }


    // plaintext passwords are bad!  Override this for your application
    protected function checkPassword($user, $password)
    {
        return $user['password'] == $password;
    }

    public function getUser($username)
    {
        $result = $this->collection('user_table')->findOne(array('username' => $username));

        return is_null($result) ? false : $result;
    }

    public function setUser($username, $password, $firstName = null, $lastName = null)
    {
        if ($this->getUser($username)) {
            $this->collection('user_table')->update(
                array('username' => $username),
                array('$set' => array(
                    'password' => $password,
                    'first_name' => $firstName,
                    'last_name' => $lastName
                ))
            );
        } else {
            $this->collection('user_table')->insert(
                array(
                    'username' => $username,
                    'password' => $password,
                    'first_name' => $firstName,
                    'last_name' => $lastName
                )
            );
        }

        return true;
    }

    public function getClientKey($client_id, $subject)
    {
        $result = $this->collection('jwt_table')->findOne(array(
            'client_id' => $client_id,
            'subject' => $subject
        ));

        return $result;
    }
}
