<?php

namespace OAuth2\Storage;

/**
 * Simple in-memory storage for all storage types
 *
 * NOTE: This class should never be used in production, and is
 * a stub class for example use only
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
class Memory implements AuthorizationCodeInterface,
    UserCredentialsInterface,
    AccessTokenInterface,
    ClientCredentialsInterface,
    RefreshTokenInterface,
    JwtBearerInterface,
    ScopeInterface,
    PublicKeyInterface
{
    private $authorizationCodes;
    private $userCredentials;
    private $clientCredentials;
    private $refreshTokens;
    private $accessTokens;
    private $jwt;
    private $supportedScopes;
    private $clientSupportedScopes;
    private $clientDefaultScopes;
    private $defaultScope;
    private $keys;

    public function __construct($params = array())
    {
        $params = array_merge(array(
            'authorization_codes' => array(),
            'user_credentials' => array(),
            'client_credentials' => array(),
            'refresh_tokens' => array(),
            'access_tokens' => array(),
            'jwt' => array(),
            'default_scope' => null,
            'client_supported_scopes' => array(),
            'client_default_scopes' => array(),
            'supported_scopes' => array(),
            'keys' => array(),
        ), $params);

        $this->authorizationCodes = $params['authorization_codes'];
        $this->userCredentials = $params['user_credentials'];
        $this->clientCredentials = $params['client_credentials'];
        $this->refreshTokens = $params['refresh_tokens'];
        $this->accessTokens = $params['access_tokens'];
        $this->jwt = $params['jwt'];
        $this->supportedScopes = $params['supported_scopes'];
        $this->clientSupportedScopes = $params['client_supported_scopes'];
        $this->clientDefaultScopes = $params['client_default_scopes'];
        $this->defaultScope = $params['default_scope'];
        $this->keys = $params['keys'];
    }

    /* AuthorizationCodeInterface */
    public function getAuthorizationCode($code)
    {
        if (!isset($this->authorizationCodes[$code])) {
            return false;
        }

        return array_merge(array(
            'authorization_code' => $code,
        ), $this->authorizationCodes[$code]);
    }

    public function setAuthorizationCode($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null)
    {
        $this->authorizationCodes[$code] = compact('code', 'client_id', 'user_id', 'redirect_uri', 'expires', 'scope');

        return true;
    }

    public function setAuthorizationCodes($authorization_codes)
    {
        $this->authorizationCodes = $authorization_codes;
    }

    public function expireAuthorizationCode($code)
    {
        unset($this->authorizationCodes[$code]);
    }

    /* UserCredentialsInterface */
    public function checkUserCredentials($username, $password)
    {
        $userDetails = $this->getUserDetails($username);
        return $userDetails && $userDetails['password'] && $userDetails['password'] === $password;
    }

    public function setUser($username, $password, $firstName = null, $lastName = null)
    {
        $this->userCredentials[$username] = array(
            'password'   => $password,
            'first_name' => $firstName,
            'last_name'  => $lastName,
        );

        return true;
    }

    public function getUserDetails($username)
    {
        if (!isset($this->userCredentials[$username])) {
            return false;
        }

        return array_merge(array(
            'user_id'    => $username,
            'password'   => null,
            'first_name' => null,
            'last_name'  => null,
        ), $this->userCredentials[$username]);
    }

    /* ClientCredentialsInterface */
    public function checkClientCredentials($client_id, $client_secret = null)
    {
        return isset($this->clientCredentials[$client_id]['client_secret']) && $this->clientCredentials[$client_id]['client_secret'] === $client_secret;
    }

    public function getClientDetails($client_id)
    {
        if (!isset($this->clientCredentials[$client_id])) {
            return false;
        }

        $clientDetails = array_merge(array(
            'client_id'     => $client_id,
            'client_secret' => null,
            'redirect_uri'  => null,
        ), $this->clientCredentials[$client_id]);

        return $clientDetails;
    }

    public function checkRestrictedGrantType($client_id, $grant_type)
    {
        if (isset($this->clientCredentials[$client_id]['grant_types'])) {
            $grant_types = explode(' ', $this->clientCredentials[$client_id]['grant_types']);

            return in_array($grant_type, $grant_types);
        }

        // if grant_types are not defined, then none are restricted
        return true;
    }

    public function setClientCredentials($client_credentials)
    {
        $this->clientCredentials = $client_credentials;
    }

    /* RefreshTokenInterface */
    public function getRefreshToken($refresh_token)
    {
        return isset($this->refreshTokens[$refresh_token]) ? $this->refreshTokens[$refresh_token] : false;
    }

    public function setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope = null)
    {
        $this->refreshTokens[$refresh_token] = compact('refresh_token', 'client_id', 'user_id', 'expires', 'scope');

        return true;
    }

    public function unsetRefreshToken($refresh_token)
    {
        unset($this->refreshTokens[$refresh_token]);
    }

    public function setRefreshTokens($refresh_tokens)
    {
        $this->refreshTokens = $refresh_tokens;
    }

    /* AccessTokenInterface */
    public function getAccessToken($access_token)
    {
        return isset($this->accessTokens[$access_token]) ? $this->accessTokens[$access_token] : false;
    }

    public function setAccessToken($access_token, $client_id, $user_id, $expires, $scope = null)
    {
        $this->accessTokens[$access_token] = compact('access_token', 'client_id', 'user_id', 'expires', 'scope');

        return true;
    }

    public function scopeExists($scope, $client_id = null)
    {
        $scope = explode(' ', trim($scope));

        if (!is_null($client_id) && array_key_exists($client_id, $this->clientSupportedScopes)) {
            $allowedScopes = array_merge($this->supportedScopes, $this->clientSupportedScopes[$client_id]);
        } else {
            $allowedScopes = $this->supportedScopes;
        }

        return (count(array_diff($scope, $allowedScopes)) == 0);
    }

    public function getDefaultScope($client_id = null)
    {
        if ($client_id && array_key_exists($client_id, $this->clientDefaultScopes)) {
           return implode(' ', $this->clientDefaultScopes[$client_id]);
        }else{
           return $this->defaultScope;
        }
    }

    /*JWTBearerInterface */
    public function getClientKey($client_id, $subject)
    {
        if (isset($this->jwt[$client_id])) {
            $jwt = $this->jwt[$client_id];
            if ($jwt) {
                if ($jwt["subject"] == $subject) {
                    return $jwt["key"];
                }
            }
        }

        return false;
    }

    /*PublicKeyInterface */
    public function getPublicKey($client_id = null)
    {
        if (isset($this->keys[$client_id])) {
            return $this->keys[$client_id]['public_key'];
        }

        // use a global encryption pair
        if (isset($this->keys['public_key'])) {
            return $this->keys['public_key'];
        }

        return false;
    }

    public function getPrivateKey($client_id = null)
    {
        if (isset($this->keys[$client_id])) {
            return $this->keys[$client_id]['private_key'];
        }

        // use a global encryption pair
        if (isset($this->keys['private_key'])) {
            return $this->keys['private_key'];
        }

        return false;
    }

    public function getEncryptionAlgorithm($client_id = null)
    {
        if (isset($this->keys[$client_id]['encryption_algorithm'])) {
            return $this->keys[$client_id]['encryption_algorithm'];
        }

        // use a global encryption algorithm
        if (isset($this->keys['encryption_algorithm'])) {
            return $this->keys['encryption_algorithm'];
        }

        return 'RS256';
    }
}
