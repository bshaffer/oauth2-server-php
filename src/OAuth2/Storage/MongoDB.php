<?php

namespace OAuth2\Storage;

use OAuth2\OpenID\Storage\AuthorizationCodeInterface as OpenIDAuthorizationCodeInterface;

use MongoDB\Driver\Manager;
use MongoDB\Driver\BulkWrite;
use MongoDB\Driver\Query;

/**
 * Simple MongoDB storage for all storage types
 *
 * NOTE: This class is meant to get users started
 * quickly. If your application requires further
 * customization, extend this class or create your own.
 *
 * NOTE: Passwords are stored in plaintext, which is never
 * a good idea.  Be sure to override this for your application
 *
 * @author Roman Shuplov <astronin@gmail.com>
 */
class MongoDB implements AuthorizationCodeInterface,
    AccessTokenInterface,
    ClientCredentialsInterface,
    UserCredentialsInterface,
    RefreshTokenInterface,
    JwtBearerInterface,
    OpenIDAuthorizationCodeInterface
{
    protected $db;
    protected $database;
    protected $config;

    public function __construct($connection, $config = array())
    {
        if (is_string ($connection)) {
            $this->db = new Manager($connection);
            if (preg_match('/^mongodb:\\/\\/.+\\/([^?&]+)/s', $connection, $matches)) {
                $this->database = $matches[1];
            } else {
                throw new \InvalidArgumentException("Unable to determine Database Name from dsn.");
            }
        } elseif (is_array($connection)) {
            $a = array('mongodb://');
            if (!empty($connection['username'])) {
                $a[] = $connection['username'] . ':';
            }
            if (!empty($connection['password'])) {
                $a[] = rawurlencode($connection['password']) . '@';
            }
            if (!empty($connection['host'])) {
                $a[] = $connection['host'];
            }
            if (!empty($connection['port'])) {
                $a[] = ':' . $connection['port'];
            }
            if (!empty($connection['database'])) {
                $a[] = '/' . $connection['database'];
                $this->database = $connection['database'];
            }
            $dsn = implode('', $a);
            
            $o = !empty($connection['options']) ? $connection['options'] : array();
            $options = array_merge(array(
                'w' => \MongoDB\Driver\WriteConcern::MAJORITY,
                'j' => true,
                'readPreference' => \MongoDB\Driver\ReadPreference::RP_NEAREST
            ), $o);
            $driverOptions = !empty($connection['driverOptions']) ? $connection['driverOptions'] : array();
            
            $this->db = new Manager($dsn, $options, $driverOptions);
        } else {
            throw new \InvalidArgumentException('First argument to OAuth2\Storage\MongoDB must be a string or a configuration array');
        }
        
        $this->db->selectServer($this->db->getReadPreference());

        $this->config = array_merge(array(
            'client_table' => 'oauth_clients',
            'access_token_table' => 'oauth_access_tokens',
            'refresh_token_table' => 'oauth_refresh_tokens',
            'code_table' => 'oauth_authorization_codes',
            'user_table' => 'oauth_users',
            'jwt_table' => 'oauth_jwt',
        ), $config);
    }

    /* ClientCredentialsInterface */
    public function checkClientCredentials($client_id, $client_secret = null)
    {
        if ($result = $this->findOne('client_table', array('client_id' => $client_id))) {
            return $result['client_secret'] == $client_secret;
        }
        return false;
    }

    /**
     * @param string $client_id
     * @return boolean
     */
    public function isPublicClient($client_id)
    {
        if (!$result = $this->findOne('client_table', array('client_id' => $client_id))) {
            return false;
        }
        return empty($result['client_secret']);
    }

    /* ClientInterface */
    public function getClientDetails($client_id)
    {
        return $this->findOne('client_table', array('client_id' => $client_id));
    }

    public function setClientDetails($client_id, $client_secret = null, $redirect_uri = null, $grant_types = null, $scope = null, $user_id = null)
    {
        $bulk = new BulkWrite();
        $bulk->update(
            array('client_id' => $client_id), 
            array('$set' => array(
                'client_id'     => $client_id,
                'client_secret' => $client_secret,
                'redirect_uri'  => $redirect_uri,
                'grant_types'   => $grant_types,
                'scope'         => $scope,
                'user_id'       => $user_id,
            )),
            array('upsert' => true)
        );
        $this->db->executeBulkWrite($this->collection('client_table'), $bulk);
        return true;
    }
    
    public function unsetClientDetails($client_id)
    {
        $this->delete('client_table', array('client_id' => $client_id));
        return true;
    }

    public function checkRestrictedGrantType($client_id, $grant_type)
    {
        if ($details = $this->getClientDetails($client_id)) {
            if (isset($details['grant_types'])) {
                $grant_types = explode(' ', $details['grant_types']);
                return in_array($grant_type, $grant_types);
            }
        }

        // if grant_types are not defined, then none are restricted
        return true;
    }

    /* AccessTokenInterface */
    public function getAccessToken($access_token)
    {
        return $this->findOne('access_token_table', array('access_token' => $access_token));
    }

    public function setAccessToken($access_token, $client_id, $user_id, $expires, $scope = null)
    {
        $bulk = new BulkWrite();
        $bulk->update(
            array('access_token' => $access_token), 
            array('$set' => array(
                'access_token' => $access_token,
                'client_id' => $client_id,
                'expires' => $expires,
                'user_id' => $user_id,
                'scope' => $scope
            )),
            array('upsert' => true)
        );
        $this->db->executeBulkWrite($this->collection('access_token_table'), $bulk);
        return true;
    }

    public function unsetAccessToken($access_token)
    {
        $this->delete('access_token_table', array('access_token' => $access_token));
        return true;
    }


    /* AuthorizationCodeInterface */
    public function getAuthorizationCode($code)
    {
        return  $this->findOne('code_table', array('authorization_code' => $code));
    }

    public function setAuthorizationCode($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null, $id_token = null)
    {
        $bulk = new BulkWrite();
        $bulk->update(
            array('authorization_code' => $code), 
            array('$set' => array(
                'authorization_code' => $code,
                'client_id' => $client_id,
                'user_id' => $user_id,
                'redirect_uri' => $redirect_uri,
                'expires' => $expires,
                'scope' => $scope,
                'id_token' => $id_token,
            )),
            array('upsert' => true)
        );
        $this->db->executeBulkWrite($this->collection('code_table'), $bulk);
        return true;
    }

    public function expireAuthorizationCode($code)
    {
        $this->delete('code_table', array('authorization_code' => $code));
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
        return $this->findOne('refresh_token_table', array('refresh_token' => $refresh_token));
    }

    public function setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope = null)
    {
        $bulk = new BulkWrite();
        $bulk->update(
            array('refresh_token' => $refresh_token), 
            array('$set' => array(
                'refresh_token' => $refresh_token,
                'client_id' => $client_id,
                'user_id' => $user_id,
                'expires' => $expires,
                'scope' => $scope
            )),
            array('upsert' => true)
        );
        $this->db->executeBulkWrite($this->collection('refresh_token_table'), $bulk);
        return true;
    }

    public function unsetRefreshToken($refresh_token)
    {
        $this->delete('refresh_token_table', array('refresh_token' => $refresh_token));
        return true;
    }

    // plaintext passwords are bad!  Override this for your application
    protected function checkPassword($user, $password)
    {
        return $user['password'] == $password;
    }

    public function getUser($username)
    {
        return $this->findOne('user_table', array('username' => $username));
    }

    public function setUser($username, $password, $firstName = null, $lastName = null)
    {
        $bulk = new BulkWrite();
        $bulk->update(
            array('username' => $username), 
            array('$set' => array(
                'username' => $username,
                'password' => $password,
                'first_name' => $firstName,
                'last_name' => $lastName
            )),
            array('upsert' => true)
        );
        $this->db->executeBulkWrite($this->collection('user_table'), $bulk);
        return true;
    }

    public function getClientKey($client_id, $subject)
    {
        $result = $this->findOne('jwt_table', array(
            'client_id' => $client_id,
            'subject' => $subject
        ));
        return $result ? $result['key'] : false;
    }

    public function getClientScope($client_id)
    {
        if (!$clientDetails = $this->getClientDetails($client_id)) {
            return false;
        }

        if (isset($clientDetails['scope'])) {
            return $clientDetails['scope'];
        }

        return null;
    }

    public function getJti($client_id, $subject, $audience, $expiration, $jti)
    {
        //TODO: Needs mongodb implementation.
        throw new \Exception('getJti() for the MongoDB driver is currently unimplemented.');
    }

    public function setJti($client_id, $subject, $audience, $expiration, $jti)
    {
        //TODO: Needs mongodb implementation.
        throw new \Exception('setJti() for the MongoDB driver is currently unimplemented.');
    }
    
    
    protected function collection($name)
    {
        return $this->database . '.' . $this->config[$name];
    }
    
    /**
     * 
     * @param string $collection
     * @param array $filter
     * @return array | false
     */
    protected function findOne($collection, $filter) 
    {
        $query = new Query($filter, array('limit' => 1, array('sort' => array('_id' => -1))));
        $cursor = $this->db
                ->executeQuery($this->collection($collection), $query);
        $cursor->setTypeMap(array(
            'root' => 'array',
            'document' => 'array'
        ));
        $result = $cursor->toArray();
        return current($result);
    }
    
    /**
     * 
     * @param string $collection
     * @param array $filter
     * @return boolean
     */
    protected function delete($collection, $filter)
    {
        $bulk = new BulkWrite();
        $bulk->delete($filter);
        $this->db->executeBulkWrite($this->collection($collection), $bulk);
        return true;
    }
}
