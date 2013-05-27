<?php

/**
 * Simple in-memory storage for all storage types
 *
 * NOTE: This class should never be used in production, and is
 * a stub class for example use only
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
class OAuth2_Storage_Memory implements OAuth2_Storage_AuthorizationCodeInterface,
    OAuth2_Storage_UserCredentialsInterface, OAuth2_Storage_AccessTokenInterface,
    OAuth2_Storage_ClientCredentialsInterface, OAuth2_Storage_RefreshTokenInterface,
    OAuth2_Storage_JWTBearerInterface, OAuth2_Storage_ScopeInterface
{
    private $authorizationCodes;
    private $userCredentials;
    private $clientCredentials;
    private $refreshTokens;
    private $accessTokens;
    private $jwt;
    private $supportedScopes;
    private $clientSupportedScopes;
    private $defaultScope;

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
            'supported_scopes' => array(),
        ), $params);

        $this->authorizationCodes = $params['authorization_codes'];
        $this->userCredentials = $params['user_credentials'];
        $this->clientCredentials = $params['client_credentials'];
        $this->refreshTokens = $params['refresh_tokens'];
        $this->accessTokens = $params['access_tokens'];
        $this->jwt = $params['jwt'];
        $this->supportedScopes = $params['supported_scopes'];
        $this->clientSupportedScopes = $params['client_supported_scopes'];
        $this->defaultScope = $params['default_scope'];
    }

    /* AuthorizationCodeInterface */
    public function getAuthorizationCode($code)
    {
        if (isset($this->authorizationCodes[$code])) {
            return $this->authorizationCodes[$code];
        }

        return null;
    }

    public function setAuthorizationCode($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null)
    {
        $this->authorizationCodes[$code] = compact('code', 'client_id', 'user_id', 'redirect_uri', 'expires', 'scope');
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
        return isset($this->userCredentials[$username]) && $this->userCredentials[$username] === $password;
    }

    public function getUserDetails($username)
    {
        if (!isset($this->userCredentials[$username])) {
            return null;
        }

        return array(
            'user_id'  => $username,
            'password' => $this->userCredentials[$username],
        );
    }

    /* ClientCredentialsInterface */
    public function checkClientCredentials($client_id, $client_secret = null)
    {
        return isset($this->clientCredentials[$client_id]['secret']) && $this->clientCredentials[$client_id]['secret'] === $client_secret;
    }

    public function getClientDetails($client_id)
    {
        if (isset($this->clientCredentials[$client_id])) {
            return $this->clientCredentials[$client_id];
        }

        return null;
    }

    public function checkRestrictedGrantType($client_id, $grant_type)
    {
        if (isset($this->clientCredentials[$client_id]['grant_types'])) {
            return in_array($grant_type, (array) $this->clientCredentials[$client_id]['grant_types']);
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
        return isset($this->refreshTokens[$refresh_token]) ? $this->refreshTokens[$refresh_token] : null;
    }

    public function setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope = null)
    {
        $this->refreshTokens[$refresh_token] = compact('refresh_token', 'client_id', 'user_id', 'expires', 'scope');
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
        return isset($this->accessTokens[$access_token]) ? $this->accessTokens[$access_token] : null;
    }

    public function setAccessToken($access_token, $client_id, $user_id, $expires, $scope = null)
    {
        $this->accessTokens[$access_token] = compact('access_token', 'client_id', 'user_id', 'expires', 'scope');
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

    public function getDefaultScope()
    {
        return $this->defaultScope;
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

        return null;
    }
}
