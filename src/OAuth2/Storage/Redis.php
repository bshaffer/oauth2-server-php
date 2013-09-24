<?php

namespace OAuth2\Storage;

/**
 * redis storage for all storage types
 *
 * Register client:
 * <code>
 *  $storage = new OAuth2_Storage_Redis($redis);
 *  $storage->registerClient($client_id, $client_secret, $redirect_uri);
 * </code>
 */
class Redis implements AuthorizationCodeInterface,
    AccessTokenInterface,
    ClientCredentialsInterface,
    UserCredentialsInterface,
    RefreshTokenInterface,
    JwtBearerInterface,
    ScopeInterface
{

    private $cache;

    /* The redis client */
    protected $redis;

    /* Configuration array */
    protected $config;

    /**
     * Redis Storage!
     *
     * @param \Predis\Client $redis
     * @param array $config
     */
    public function __construct($redis, $config=array())
    {
        $this->redis = $redis;
        $this->config = array_merge(array(
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
        if ( isset($this->cache[$key]) ) {
            return $this->cache[$key];
        }
        $value = $this->redis->get($key);
        if ( isset($value) ) {
            return json_decode($value, true);
        } else {
            return false;
        }
    }

    protected function setValue($key, $value, $expire=0)
    {
        $this->cache[$key] = $value;
        $str = json_encode($value);
        if ( $expire > 0 ) {
            $seconds = $expire - time();
            return $this->redis->setex($key, $seconds, $str);
        } else {
            return $this->redis->set($key, $str);
        }
    }

    protected function expireValue($key)
    {
        unset($this->cache[$key]);
        return $this->redis->expire($key);
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
        $client = $this->getClientDetails($client_id);
        return isset($client['client_secret'])
            && $client['client_secret'] == $client_secret;
    }

    public function getClientDetails($client_id)
    {
        return $this->getValue($this->config['client_key'] . $client_id);
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

    public function registerClient($client_id, $client_secret, $redirect_uri)
    {
        return $this->setValue(
            $this->config['client_key'] . $client_id,
            compact('client_id', 'client_secret', 'redirect_uri')
        );
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

    /*JWTBearerInterface */
    public function getClientKey($client_id, $subject)
    {
        $jwt = $this->getValue($this->config['jwt_key'] . $client_id);
        if ( isset($jwt['subject']) && $jwt['subject'] == $subject ) {
            return $jwt['key'];
        }
        return null;
    }
}
