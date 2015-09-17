<?php

namespace OAuth2\Storage;

use OAuth2\OpenID\Storage\UserClaimsInterface;
use OAuth2\OpenID\Storage\AuthorizationCodeInterface as OpenIDAuthorizationCodeInterface;

/**
 * Cassandra storage based on CQL
 * 
 * This storage uses the datastax php-driver for cassandra
 * https://github.com/datastax/php-driver
 * 
 * <code>
 *  $cassandraCluster = \Cassandra::cluster()->withContactPoints('192.168.0.100')->withPort(9042)->build();
 *  $cassandraSession = $cassandraCluster->connect( 'my_keyspace' );
 * </code>
 *
 * You need the following tables in cassandra for this storage
 * <code>
 *   $sql = "CREATE TABLE IF NOT EXISTS ".$this->config['column_family_data']." (key varchar, data text, PRIMARY KEY(key))";
 *   $statement = new \Cassandra\SimpleStatement($sql);
 *   $result = $this->getSession()->execute($statement);
 *
 *   $sql = "CREATE TABLE IF NOT EXISTS ".$this->config['column_family_clients']." (key text, data text, PRIMARY KEY(key))";
 *   $statement = new \Cassandra\SimpleStatement($sql);
 *   $result = $this->getSession()->execute($statement);
 * </code> 
 * 
 * Then, register the storage client:
 * <code>
 *  $storage = new OAuth2\Storage\Cassandra($cassandra);
 *  $storage->setClientDetails($client_id, $client_secret, $redirect_uri);
 * </code>
 *
 */
class CassandraCQL implements AuthorizationCodeInterface,
    AccessTokenInterface,
    ClientCredentialsInterface,
    UserCredentialsInterface,
    RefreshTokenInterface,
    JwtBearerInterface,
    ScopeInterface,
    PublicKeyInterface,
    UserClaimsInterface,
    OpenIDAuthorizationCodeInterface
{

    protected $cassandraSession;

    protected $config;


    public function __construct($cassandraSession, array $config = array())
    {
        $this->cassandraSession = $cassandraSession;
        
        $this->config = array_merge(array(
            // cassandra config
            'column_family_data' => 'oauth2_data',
            'column_family_clients' => 'oauth2_clients',

            // key names
            'access_token_key' => 'oauth_access_tokens:',
            'refresh_token_key' => 'oauth_refresh_tokens:',
            'code_key' => 'oauth_authorization_codes:',
            'user_key' => 'oauth_users:',
            'jwt_key' => 'oauth_jwt:',
            'scope_key' => 'oauth_scopes:',
            'public_key_key'  => 'oauth_public_keys:',
        ), $config);

        /*
        $sql = "CREATE TABLE IF NOT EXISTS ".$this->config['column_family_data']." (key varchar, data text, PRIMARY KEY(key))";
        $statement = new \Cassandra\SimpleStatement($sql);
        $result = $this->getSession()->execute($statement);

        $sql = "CREATE TABLE IF NOT EXISTS ".$this->config['column_family_clients']." (key text, data text, PRIMARY KEY(key))";
        $statement = new \Cassandra\SimpleStatement($sql);
        $result = $this->getSession()->execute($statement);
        */
    }

    protected function getSession()
    {
        return $this->cassandraSession;
    }

    protected function getValue($key)
    {
        $sql = "SELECT * FROM ".$this->config['column_family_data']. " WHERE key = '".$key."' ";
        $statement = new \Cassandra\SimpleStatement($sql);
        $result = $this->getSession()->execute($statement);
        if ($result->count() === 0)
        {
          return null;
        }
        $row = $result[0];
        return json_decode($row['data'], true);

        
    }

    protected function setValue($key, $value, $expire = 0)
    {
        $str = json_encode($value);
        $sql = "UPDATE ".$this->config['column_family_data']." SET data='".$str."' WHERE key='".$key."'";
        $this->getSession()->execute(new \Cassandra\SimpleStatement($sql));
        return true;
    }

    protected function expireValue($key)
    {
        $sql = "DELETE FROM ".$this->config['column_family_data']." WHERE key='".$key."' ";
        $this->getSession()->execute(new \Cassandra\SimpleStatement($sql));
        return true;
    }

    /* AuthorizationCodeInterface */
    public function getAuthorizationCode($code)
    {
        return $this->getValue($this->config['code_key'] . $code);
    }

    public function setAuthorizationCode($authorization_code, $client_id, $user_id, $redirect_uri, $expires, $scope = null, $id_token = null)
    {
        return $this->setValue(
            $this->config['code_key'] . $authorization_code,
            compact('authorization_code', 'client_id', 'user_id', 'redirect_uri', 'expires', 'scope', 'id_token'),
            $expires
        );
    }

    public function expireAuthorizationCode($code)
    {
        $key = $this->config['code_key'] . $code;

        return $this->expireValue($key);
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
        return $user['password'] == sha1($password);
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
        $password = sha1($password);

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
        $sql = "SELECT * FROM ".$this->config['column_family_clients']. " WHERE key = '".$client_id."' ";
        $statement = new \Cassandra\SimpleStatement($sql);
        $result = $this->getSession()->execute($statement);
        if ($result->count() === 0)
        {
          return null;
        }
        $row = $result[0];
        return json_decode($row['data'], true);
    }

    public function setClientDetails($client_id, $client_secret = null, $redirect_uri = null, $grant_types = null, $scope = null, $user_id = null)
    {
        $value = compact('client_id', 'client_secret', 'redirect_uri', 'grant_types', 'scope', 'user_id');
        $str = json_encode($value);
        
        $sql = "UPDATE ".$this->config['column_family_clients']." SET data='".$str."' WHERE key='".$client_id."'";
        $this->getSession()->execute(new \Cassandra\SimpleStatement($sql));
        return true;
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

    public function unsetAccessToken($access_token)
    {
        return $this->expireValue($this->config['access_token_key'] . $access_token);
    }

    /* ScopeInterface */
    public function scopeExists($scope)
    {
        $scope = explode(' ', $scope);

        $result = $this->getValue($this->config['scope_key'].'supported:global');

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
        if (!$jwt = $this->getValue($this->config['jwt_key'] . $client_id)) {
            return false;
        }

        if (isset($jwt['subject']) && $jwt['subject'] == $subject ) {
            return $jwt['key'];
        }

        return null;
    }

    public function setClientKey($client_id, $key, $subject = null)
    {
        return $this->setValue($this->config['jwt_key'] . $client_id, array(
            'key' => $key,
            'subject' => $subject
        ));
    }

    /*ScopeInterface */
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

    /* PublicKeyInterface */
    public function getPublicKey($client_id = '')
    {
        $public_key = $this->getValue($this->config['public_key_key'] . $client_id);
        if (is_array($public_key)) {
            return $public_key['public_key'];
        }
        $public_key = $this->getValue($this->config['public_key_key']);
        if (is_array($public_key)) {
            return $public_key['public_key'];
        }
    }

    public function getPrivateKey($client_id = '')
    {
        $public_key = $this->getValue($this->config['public_key_key'] . $client_id);
        if (is_array($public_key)) {
            return $public_key['private_key'];
        }
        $public_key = $this->getValue($this->config['public_key_key']);
        if (is_array($public_key)) {
            return $public_key['private_key'];
        }
    }

    public function getEncryptionAlgorithm($client_id = null)
    {
        $public_key = $this->getValue($this->config['public_key_key'] . $client_id);
        if (is_array($public_key)) {
            return $public_key['encryption_algorithm'];
        }
        $public_key = $this->getValue($this->config['public_key_key']);
        if (is_array($public_key)) {
            return $public_key['encryption_algorithm'];
        }

        return 'RS256';
    }

    /* UserClaimsInterface */
    public function getUserClaims($user_id, $claims)
    {
        $userDetails = $this->getUserDetails($user_id);
        if (!is_array($userDetails)) {
            return false;
        }

        $claims = explode(' ', trim($claims));
        $userClaims = array();

        // for each requested claim, if the user has the claim, set it in the response
        $validClaims = explode(' ', self::VALID_CLAIMS);
        foreach ($validClaims as $validClaim) {
            if (in_array($validClaim, $claims)) {
                if ($validClaim == 'address') {
                    // address is an object with subfields
                    $userClaims['address'] = $this->getUserClaim($validClaim, $userDetails['address'] ?: $userDetails);
                } else {
                    $userClaims = array_merge($userClaims, $this->getUserClaim($validClaim, $userDetails));
                }
            }
        }

        return $userClaims;
    }

    protected function getUserClaim($claim, $userDetails)
    {
        $userClaims = array();
        $claimValuesString = constant(sprintf('self::%s_CLAIM_VALUES', strtoupper($claim)));
        $claimValues = explode(' ', $claimValuesString);

        foreach ($claimValues as $value) {
            if ($value == 'email_verified') {
                $userClaims[$value] = $userDetails[$value]=='true' ? true : false;
            } else {
                $userClaims[$value] = isset($userDetails[$value]) ? $userDetails[$value] : null;
            }
        }

        return $userClaims;
    }

}
