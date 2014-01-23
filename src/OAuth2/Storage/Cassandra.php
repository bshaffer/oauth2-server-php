<?php

namespace OAuth2\Storage;
use phpcassa\ColumnFamily;
use phpcassa\ColumnSlice;
use phpcassa\Connection\ConnectionPool;

/**
 * cassandra storage for all storage types, requires phpcassa
 *
 * To use, install "thobbs/phpcassa" via composer
 *
 * Register client:
 * <code>
 *  $storage = new OAuth2\Storage\Cassandra($cassandra);
 *  $storage->setClientDetails($client_id, $client_secret, $redirect_uri);
 * </code>
 */
class Cassandra implements AuthorizationCodeInterface,
    AccessTokenInterface,
    ClientCredentialsInterface,
    UserCredentialsInterface,
    RefreshTokenInterface,
    JwtBearerInterface,
    ScopeInterface
{

    private $cache;

    /* The cassandra client */
    protected $cassandra;

    /* Configuration array */
    protected $config;

    /**
     * Cassandra Storage! uses phpCassa
     *
     * @param \phpcassa\ConnectionPool $cassandra
     * @param array $config
     */
    public function __construct($connection = array(), array $config = array())
    {
        if ($connection instanceof ConnectionPool) {
            $this->cassandra = $connection;
        } else {
            if (!is_array($connection)) {
                throw new \InvalidArgumentException('First argument to OAuth2\Storage\Mongo must be an instance of MongoDB or a configuration array');
            }
            $connection = array_merge(array(
                'keyspace' => 'oauth2',
                'servers'  => null,
            ), $connection);

            $this->cassandra = new ConnectionPool($connection['keyspace'], $connection['servers']);
        }

        $this->config = array_merge(array(
            // key names
            'client_key' => 'oauth_clients:',
            'access_token_key' => 'oauth_access_tokens:',
            'refresh_token_key' => 'oauth_refresh_tokens:',
            'code_key' => 'oauth_authorization_codes:',
            'user_key' => 'oauth_users:',
            'jwt_key' => 'oauth_jwt:',
            'scope_key' => 'oauth_scopes:',
        ), $config);
    }

    protected function getValue($key)
    {
        if (isset($this->cache[$key])) {
            return $this->cache[$key];
        }

        preg_match("/^(.+?)\:(.+)$/", $key, $parts);
        list($cf_key, $cf_name, $key) = $parts;

        $cf = new \phpcassa\ColumnFamily($this->cassandra, $cf_name);

        try {
            $value = array_map('__backend_data_decode', $cf->get($key, new ColumnSlice("", "")));
            return $value;
        } catch (\cassandra\NotFoundException $e) {
            return false;
        }
    }

    protected function setValue($key, $value, $expire = 0)
    {
        $this->cache[$key] = $value;

        preg_match("/^(.+?)\:(.+)$/", $key, $parts);
        list($cf_key, $cf_name, $key) = $parts;

        $cf = new ColumnFamily($this->cassandra, $cf_name);

        if ($expire > 0) {
            try {
                $seconds = $expire - time();
                // __data key set as C* requires a field, note: max TTL can only be 630720000 seconds
                $cf->insert($key, array_map('__backend_data_encode', $value), null, $seconds);
            } catch(\Exception $e) {
                return false;
            }
        } else {
            try {
                // __data key set as C* requires a field
                $cf->insert($key, array_map('__backend_data_encode', $value));
            } catch(\Exception $e) {
                return false;
            }
        }

        return true;
    }

    protected function expireValue($key)
    {
        unset($this->cache[$key]);

        preg_match("/^(.+?)\:(.+)$/", $key, $parts);
        list($cf_key, $cf_name, $key) = $parts;

        $cf = new ColumnFamily($this->cassandra, $cf_name);
        try {
            // __data key set as C* requires a field
            $cf->remove($key);
        } catch(\Exception $e) {
            return false;
        }

        return true;
    }

    /* AuthorizationCodeInterface */
    public function getAuthorizationCode($code)
    {
        return $this->getValue($this->config['code_key'] . $code);
    }

    public function setAuthorizationCode($authorization_code, $client_id, $user_id, $redirect_uri, $expires, $scope = null)
    {
        return $this->setValue(
            $this->config['code_key'] . $authorization_code,
            compact('authorization_code', 'client_id', 'user_id', 'redirect_uri', 'expires', 'scope'),
            $expires
        );
    }

    public function expireAuthorizationCode($code)
    {
        $key = $this->config['code_key'] . $code;
        unset($this->cache[$key]);

        return $this->expireValue($key);
    }

    /* UserCredentialsInterface */
    public function checkUserCredentials($username, $password)
    {
        $user = $this->getUserDetails($username);

        return $user && $user['password'] === $password;
    }

    public function getUserDetails($username)
    {
        return $this->getUser($username);
    }

    public function getUser($username)
    {
        if (!$userInfo = $this->getValue($this->config['user_key'] . $username)) {
            return false;
        }

        // the default behavior is to use "username" as the user_id
        return array_merge(array(
            'user_id' => $username,
        ), $userInfo);
    }

    public function setUser($username, $password, $first_name = null, $last_name = null)
    {
        return $this->setValue(
            $this->config['user_key'] . $username,
            compact('username', 'password', 'first_name', 'last_name')
        );
    }

    /* ClientCredentialsInterface */
    public function checkClientCredentials($client_id, $client_secret = null)
    {
        if (!$client = $this->getClientDetails($client_id)) {
            return false;
        }

        return isset($client['client_secret'])
            && $client['client_secret'] == $client_secret;
    }

    public function isPublicClient($client_id)
    {
        if (!$client = $this->getClientDetails($client_id)) {
            return false;
        }

        return empty($result['client_secret']);;
    }

    /* ClientInterface */
    public function getClientDetails($client_id)
    {
        return $this->getValue($this->config['client_key'] . $client_id);
    }

    public function setClientDetails($client_id, $client_secret = null, $redirect_uri = null, $grant_types = null, $scope = null, $user_id = null)
    {
        return $this->setValue(
            $this->config['client_key'] . $client_id,
            compact('client_id', 'client_secret', 'redirect_uri', 'grant_types', 'scope', 'user_id')
        );
    }

    public function checkRestrictedGrantType($client_id, $grant_type)
    {
        $details = $this->getClientDetails($client_id);
        if (isset($details['grant_types'])) {
            $grant_types = explode(' ', $details['grant_types']);

            return in_array($grant_type, (array) $grant_types);
        }

        // if grant_types are not defined, then none are restricted
        return true;
    }

    /* RefreshTokenInterface */
    public function getRefreshToken($refresh_token)
    {
        return $this->getValue($this->config['refresh_token_key'] . $refresh_token);
    }

    public function setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope = null)
    {
        return $this->setValue(
            $this->config['refresh_token_key'] . $refresh_token,
            compact('refresh_token', 'client_id', 'user_id', 'expires', 'scope'),
            $expires
        );
    }

    public function unsetRefreshToken($refresh_token)
    {
        return $this->expireValue($this->config['refresh_token_key'] . $refresh_token);
    }

    /* AccessTokenInterface */
    public function getAccessToken($access_token)
    {
        return $this->getValue($this->config['access_token_key'].$access_token);
    }

    public function setAccessToken($access_token, $client_id, $user_id, $expires, $scope = null)
    {
        return $this->setValue(
            $this->config['access_token_key'].$access_token,
            compact('access_token', 'client_id', 'user_id', 'expires', 'scope'),
            $expires
        );
    }

    /* ScopeInterface */
    public function scopeExists($scope, $client_id = null)
    {
        $scope = explode(' ', $scope);
        if (is_null($client_id) || !$result = $this->getValue($this->config['scope_key'].'supported:'.$client_id)) {
            $result = $this->getValue($this->config['scope_key'].'supported:global');
        }
        $supportedScope = explode(' ', (string) $result);

        return (count(array_diff($scope, $supportedScope)) == 0);
    }

    public function getDefaultScope($client_id = null)
    {
        if (is_null($client_id) || !$result = $this->getValue($this->config['scope_key'].'default:'.$client_id)) {
            $result = $this->getValue($this->config['scope_key'].'default:global');
        }

        return $result;
    }

    public function setScope($scope, $client_id = null, $type = 'supported')
    {
        if (!in_array($type, array('default', 'supported'))) {
            throw new \InvalidArgumentException('"$type" must be one of "default", "supported"');
        }

        if (is_null($client_id)) {
            $key = $this->config['scope_key'].$type.':global';
        } else {
            $key = $this->config['scope_key'].$type.':'.$client_id;
        }

        return $this->setValue($key, $scope);
    }

    /*JWTBearerInterface */
    public function getClientKey($client_id, $subject)
    {
        $jwt = $this->getValue($this->config['jwt_key'] . $client_id);
        if (isset($jwt['subject']) && $jwt['subject'] == $subject ) {
            return $jwt['key'];
        }

        return null;
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
        //TODO: Needs cassandra implementation.
        throw new \Exception('getJti() for the Cassandra driver is currently unimplemented.');
    }

    public function setJti($client_id, $subject, $audience, $expiration, $jti)
    {
        //TODO: Needs cassandra implementation.
        throw new \Exception('setJti() for the Cassandra driver is currently unimplemented.');
    }
}


function __backend_data_encode($value)
{
    //print_r($value);
    if (gettype($value) == "array" || gettype($value) == "object")
    {
        return '_json:' . json_encode($value);
    }
    
    return $value;

}

function __backend_data_decode($value)
{
    //print_r($value);
    if (strpos($value, '_json:') !== false)
    {
        return json_decode(substr($value, 6), true);
    }

    return $value;
}
