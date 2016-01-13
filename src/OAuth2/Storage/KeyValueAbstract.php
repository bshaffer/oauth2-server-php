<?php
namespace OAuth2\Storage;

use OAuth2\OpenID\Storage\UserClaimsInterface;
use OAuth2\OpenID\Storage\AuthorizationCodeInterface as OpenIDAuthorizationCodeInterface;

abstract class KeyValueAbstract implements
    AuthorizationCodeInterface,
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

    const KEY_GLOBAL = 'global';

    protected $config = array(
        'client_table' => 'oauth_clients',
        'access_token_table' => 'oauth_access_tokens',
        'refresh_token_table' => 'oauth_refresh_tokens',
        'code_table' => 'oauth_authorization_codes',
        'user_table' => 'oauth_users',
        'jwt_table' => 'oauth_jwt',
        'jti_table' => 'oauth_jti',
        'scope_table' => 'oauth_scopes',
        'public_key_table' => 'oauth_public_keys'
    );

    /**
     *
     * @param string $table
     * @param string $key
     * @return mixed
     */
    abstract protected function get($table, $key);

    /**
     *
     * @param string $table
     * @param string $key
     * @param mixed $value
     * @return bool
     */
    abstract protected function set($table, $key, $value);

    /**
     *
     * @param string $table
     * @param string $key
     * @return bool
     */
    abstract protected function delete($table, $key);

    protected static function _hash($data)
    {
        return hash('sha256', json_encode($data));
    }
    
    // AuthorizationCodeInterface
    public function getAuthorizationCode($authorization_code)
    {
        $result = $this->get($this->config['code_table'], $authorization_code);
        if (is_array($result)) {
            return $result;
        }
        
        //return null;
        return false;
    }

    public function setAuthorizationCode($authorization_code, $client_id, $user_id, $redirect_uri, $expires, $scope = null, $id_token = null)
    {
        return $this->set($this->config['code_table'], $authorization_code, compact('authorization_code', 'client_id', 'user_id', 'redirect_uri', 'expires', 'scope', 'id_token'));
    }

    public function expireAuthorizationCode($authorization_code)
    {
        $this->delete($this->config['code_table'], $authorization_code);
    }

    // AccessTokenInterface
    public function getAccessToken($access_token)
    {
        $result = $this->get($this->config['access_token_table'], $access_token);
        
        if (is_array($result)) {
            return $result;
        }
        
        //return null;
        return false;
    }

    public function setAccessToken($access_token, $client_id, $user_id, $expires, $scope = null)
    {
        return $this->set($this->config['access_token_table'], $access_token, compact('access_token', 'client_id', 'user_id', 'expires', 'scope'));
    }

    public function unsetAccessToken($access_token)
    {
        $this->delete($this->config['access_token_table'], $access_token);
    }

    // ClientCredentialsInterface
    public function getClientDetails($client_id)
    {
        $client = $this->get($this->config['client_table'], $client_id);
        
        if (is_array($client)) {
            return $client;
        }
        
        return false;
    }

    public function setClientDetails($client_id, $client_secret = null, $redirect_uri = null, $grant_types = null, $scope = null, $user_id = null)
    {
        return $this->set($this->config['client_table'], $client_id, compact('client_id', 'client_secret', 'redirect_uri', 'grant_types', 'scope', 'user_id'));
    }

    public function getClientScope($client_id)
    {
        $client = $this->getClientDetails($client_id);
        
        if (isset($client['scope'])) {
            return $client['scope'];
        }
        
        return false;
    }

    public function checkRestrictedGrantType($client_id, $grant_type)
    {
        if (!$client = $this->getClientDetails($client_id)) {
            return false;
        }
        
        if (isset($client['grant_types'])) {
            return in_array($grant_type, explode(' ', $client['grant_types']));
        }
        
        // if grant_types are not defined, then none are restricted
        return true;
    }

    public function checkClientCredentials($client_id, $client_secret = null)
    {
        $client = $this->getClientDetails($client_id);
        return (isset($client['client_secret']) && $client['client_secret'] === $client_secret);
    }

    public function isPublicClient($client_id)
    {
        $client = $this->getClientDetails($client_id);
        return empty($client['client_secret']);
    }

    // UserCredentialsInterface
    public function getUserDetails($user_id)
    {
        $user = $this->get($this->config['user_table'], $user_id);
        
        if (is_array($user)) {
            // the default behavior is to use "username" as the user_id
            return array_merge(array(
                'user_id' => $user_id
            ), $user);
        }
        
        return false;
    }

    public function setUser($username, $password, $first_name = null, $last_name = null, $email = null, $email_verified = null)
    {
        $password = $this->passwordHash($password);
        return $this->set($this->config['user_table'], $username, compact('username', 'password', 'first_name', 'last_name', 'email', 'email_verified'));
    }

    // Override this for your application
    protected function passwordVerify($password, $hash)
    {
        return sha1($password) === $hash;
        // return password_verify($password, $hash);
    }

    // Override this for your application
    protected function passwordHash($password)
    {
        return sha1($password);
        // return password_hash($password, PASSWORD_BCRYPT);
    }

    public function checkUserCredentials($user_id, $password)
    {
        if (!$user = $this->getUserDetails($user_id)) {
            return false;
        }
        
        return $this->passwordVerify($password, $user['password']);
    }

    // RefreshTokenInterface
    public function getRefreshToken($refresh_token)
    {
        $result = $this->get($this->config['refresh_token_table'], $refresh_token);
        
        if (is_array($result)) {
            return $result;
        }
        
        // return null;
        return false;
    }

    public function setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope = null)
    {
        return $this->set($this->config['refresh_token_table'], $refresh_token, compact('refresh_token', 'client_id', 'user_id', 'expires', 'scope'));
    }

    public function unsetRefreshToken($refresh_token)
    {
        $this->delete($this->config['refresh_token_table'], $refresh_token);
    }

    // JwtBearerInterface
    public function getClientKey($client_id, $subject)
    {
        $keydata = compact('client_id', 'subject');
        $keystring = self::_hash($keydata);
        
        $result = $this->get($this->config['jwt_table'], $keystring);
        
        if (is_string($result)) {
            return $result;
        }
        
        return false;
    }

    public function setClientKey($client_id, $key, $subject = null)
    {
        $keydata = compact('client_id', 'subject');
        $keystring = self::_hash($keydata);
        
        return $this->set($this->config['jwt_table'], $keystring, $key);
    }

    public function getJti($client_id, $subject, $audience, $expiration, $jti)
    {
        $data = array(
            'issuer' => $client_id,
            'subject' => $subject,
            'audience' => $audience,
            'expires' => $expiration,
            'jti' => $jti
        );
        
        $key = self::_hash($data);
        
        $result = $this->get($this->config['jti_table'], $key);
        
        if (is_array($result)) {
            return $result;
        }
        
        return null;
    }

    public function setJti($client_id, $subject, $audience, $expiration, $jti)
    {
        $data = array(
            'issuer' => $client_id,
            'subject' => $subject,
            'audience' => $audience,
            'expires' => $expiration,
            'jti' => $jti
        );
        
        $key = self::_hash($data);
        
        $this->set($this->config['jti_table'], $key, $data);
    }

    // ScopeInterface
    public function scopeExists($scope)
    {
        $supportedScopes = $this->get($this->config['scope_table'], 'supported' . ':' . self::KEY_GLOBAL);
        if (is_string($supportedScopes)) {
            $supportedScopes = explode(' ', $supportedScopes);
            $scope = explode(' ', $scope);
            return (count(array_diff($scope, $supportedScopes)) === 0);
        }
        
        return false;
    }

    public function getDefaultScope($client_id = null)
    {
        if (is_null($client_id) || !$result = $this->get($this->config['scope_table'], 'default' . ':' . $client_id)) {
            $result = $this->get($this->config['scope_table'], 'default' . ':' . self::KEY_GLOBAL);
        }
        
        if (is_string($result)) {
            return $result;
        }
        
        return false;
    }

    public function setScope($scope, $client_id = null, $type = 'supported')
    {
        if (!in_array($type, array('default', 'supported'), true)) {
            throw new \InvalidArgumentException('"$type" must be one of "default", "supported"');
        }
        
        if (is_null($client_id)) {
            $key = $type . ':' . self::KEY_GLOBAL;
        } else {
            $key = $type . ':' . $client_id;
        }
        
        return $this->set($this->config['scope_table'], $key, $scope);
    }

    // PublicKeyInterface
    public function getPublicKey($client_id = null)
    {
        if (is_null($client_id) || !$result = $this->get($this->config['public_key_table'], $client_id)) {
            $result = $this->get($this->config['public_key_table'], '');
        }
        
        if (is_array($result)) {
            return $result['public_key'];
        }
        
        return null;
    }

    public function getPrivateKey($client_id = null)
    {
        if (is_null($client_id) || !$result = $this->get($this->config['public_key_table'], $client_id)) {
            $result = $this->get($this->config['public_key_table'], '');
        }
        
        if (is_array($result)) {
            return $result['private_key'];
        }
        
        return null;
    }

    public function getEncryptionAlgorithm($client_id = null)
    {
        if (is_null($client_id) || !$result = $this->get($this->config['public_key_table'], $client_id)) {
            $result = $this->get($this->config['public_key_table'], '');
        }
        
        if (is_array($result)) {
            return $result['encryption_algorithm'];
        }
        
        return 'RS256';
    }

    public function setServerKey($client_id, $public_key, $private_key, $encryption_algorithm)
    {
        if (is_null($client_id)) {
            $client_id = '';
        }
        
        return $this->set($this->config['public_key_table'], $client_id, compact('client_id', 'public_key', 'private_key', 'encryption_algorithm'));
    }

    // UserClaimsInterface
    public function getUserClaims($user_id, $scope)
    {
        $userDetails = $this->getUserDetails($user_id);
        if (!is_array($userDetails)) {
            return false;
        }
        
        $userClaims = array();
        $scopeValues = array_intersect(explode(' ', self::VALID_CLAIMS), explode(' ', $scope));
        foreach ($scopeValues as $scopeValue) {
            $userClaims = array_merge($userClaims, $this->getUserClaim($scopeValue, $userDetails));
        }
        
        return $userClaims;
    }

    protected function getUserClaim($scopeValue, $userDetails)
    {
        $SCOPE_ADDRESS = 'address'; // const
        
        $userClaims = array();
        $claimValuesString = constant(sprintf('self::%s_CLAIM_VALUES', strtoupper($scopeValue)));
        $claimValues = explode(' ', $claimValuesString);
        if ($scopeValue === $SCOPE_ADDRESS) {
            if (isset($userDetails[$SCOPE_ADDRESS]) && is_array($userDetails[$SCOPE_ADDRESS])) {
                $userDetails = $userDetails[$SCOPE_ADDRESS];
            }
            $addressClaims = array();
            foreach ($claimValues as $claimValue) {
                if (isset($userDetails[$claimValue])) {
                    $addressClaims[$claimValue] = $userDetails[$claimValue];
                } else {
                    $addressClaims[$claimValue] = null; // we should not return claims with null values, but this is for BC
                }
            }
            if (count($addressClaims)) {
                $userClaims[$SCOPE_ADDRESS] = $addressClaims;
            }
        } else {
            foreach ($claimValues as $claimValue) {
                if (isset($userDetails[$claimValue])) {
                    if (in_array($claimValue, array(
                        'email_verified',
                        'phone_number_verified'
                    ), true)) {
                        $userDetails[$claimValue] = (is_string($userDetails[$claimValue]) && !strcasecmp($userDetails[$claimValue], 'true')) || ((is_numeric($userDetails[$claimValue]) || is_bool($userDetails[$claimValue])) && (bool) $userDetails[$claimValue]);
                    }
                    $userClaims[$claimValue] = $userDetails[$claimValue];
                } else {
                    $userClaims[$claimValue] = null; // we should not return claims with null values, but this is for BC
                }
            }
        }
        return $userClaims;
    }
}
