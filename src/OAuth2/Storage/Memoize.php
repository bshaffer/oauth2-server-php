<?php
/**
 * Cache query in memory
 *
 * @author Ye Wenbin <wenbinye@gmail.com>
 */
class OAuth2_Storage_Memoize implements
    \OAuth2_Storage_AuthorizationCodeInterface,
    \OAuth2_Storage_UserCredentialsInterface,
    \OAuth2_Storage_AccessTokenInterface,
    \OAuth2_Storage_ClientCredentialsInterface,
    \OAuth2_Storage_RefreshTokenInterface,
    \OAuth2_Storage_JWTBearerInterface
{
    private $authorizationCodes;
    private $userDetails;
    private $clientCredentials;
    private $refreshTokens;
    private $accessTokens;
    private $jwt;
    private $storage;

    public function __construct($storage)
    {
        $this->storage = $storage;
    }
    
    /* AuthorizationCodeInterface */
    public function getAuthorizationCode($code)
    {
        if (isset($this->authorizationCodes[$code])) {
            return $this->authorizationCodes[$code];
        } else {
            return $this->authorizationCodes[$code] = $this->storage->getAuthorizationCode($code);
        }
    }

    public function setAuthorizationCode($authorization_code, $client_id, $user_id, $redirect_uri, $expires, $scope = null)
    {
        $this->authorizationCodes[$authorization_code] = compact('authorization_code', 'client_id', 'user_id', 'redirect_uri', 'expires', 'scope');
        return $this->storage->setAuthorizationCode($authorization_code, $client_id, $user_id, $redirect_uri, $expires, $scope);
    }

    public function expireAuthorizationCode($code)
    {
        unset($this->authorizationCodes[$code]);
        return $this->storage->expireAuthorizationCode($code);
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
        if ( isset($this->userDetails[$username]) ) {
            return $this->userDetails[$username];
        } else {
            return $this->userDetails[$username] = $this->storage->getUserDetails($username);
        }
    }
    
    public function setUser($username, $password, $first_name = null, $last_name = null)
    {
        $user = compact('username', 'password', 'first_name', 'last_name');
        $this->userDetails[$username] = $user;
        return $this->storage->setUser($username, $password, $first_name, $last_name);
    }

    /* ClientCredentialsInterface */
    public function checkClientCredentials($client_id, $client_secret = null)
    {
        $result = $this->getClientDetails($client_id);
        if ( $result ) {
            // make this extensible
            return $result['client_secret'] == $client_secret;
        } else {
            return false;
        }
    }

    public function getClientDetails($client_id)
    {
        if (isset($this->clientCredentials[$client_id])) {
            return $this->clientCredentials[$client_id];
        } else {
            return $this->clientCredentials[$client_id] = $this->storage->getClientDetails($client_id);
        }
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

    /* RefreshTokenInterface */
    public function getRefreshToken($refresh_token)
    {
        if ( isset($this->refreshTokens[$refresh_token]) ) {
            return $this->refreshTokens[$refresh_token];
        } else {
            return $this->refreshTokens[$refresh_token] = $this->storage->getRefreshToken($refresh_token);
        }
    }

    public function setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope = null)
    {
        $this->refreshTokens[$refresh_token] = compact('refresh_token', 'client_id', 'user_id', 'expires', 'scope');
        return $this->storage->setRefreshToken($refresh_token, $client_id, $user_id, $expires);
    }

    public function unsetRefreshToken($refresh_token)
    {
        unset($this->refreshTokens[$refresh_token]);
        return $this->storage->unsetRefreshToken($refresh_token);
    }

    /* AccessTokenInterface */
    public function getAccessToken($access_token)
    {
        if( isset($this->accessTokens[$access_token]) ) {
            return $this->accessTokens[$access_token];
        } else {
            return $this->accessTokens[$access_token] = $this->storage->getAccessToken($access_token);
        }
    }

    public function setAccessToken($access_token, $client_id, $user_id, $expires, $scope = null)
    {
        $this->accessTokens[$access_token] = compact('access_token', 'client_id', 'user_id', 'expires', 'scope');
        return $this->storage->setAccessToken($access_token, $client_id, $user_id, $expires, $scope);
    }

    /*JWTBearerInterface */
    public function getClientKey($client_id, $subject)
    {
        if (isset($this->jwt[$client_id][$subject])) {
            return $this->jwt[$client_id][$subject];
        } else {
            return $this->jwt[$client_id][$subject] = $this->storage->getClientKey($client_id, $subject);
        }
    }
}
