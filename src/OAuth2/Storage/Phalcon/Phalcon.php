<?php

namespace OAuth2\Storage\Phalcon;

use OAuth2\OpenID\Storage\AuthorizationCodeInterface as OpenIDAuthorizationCodeInterface;
use OAuth2\OpenID\Storage\UserClaimsInterface;
use OAuth2\Storage\AccessTokenInterface;
use OAuth2\Storage\AuthorizationCodeInterface;
use OAuth2\Storage\ClientCredentialsInterface;
use OAuth2\Storage\JwtBearerInterface;
use OAuth2\Storage\Phalcon\Models;
use OAuth2\Storage\PublicKeyInterface;
use OAuth2\Storage\RefreshTokenInterface;
use OAuth2\Storage\ScopeInterface;
use OAuth2\Storage\UserCredentialsInterface;

/**
 * Phalcon adapter for OAuth data storage.
 *
 * Passwords are stored in sha1 hashes.
 *
 * @author Luca Santarella <luca.santarella@gmail.com>
 */
class Phalcon implements
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
    const KEY_PHALCON_CONFIG_ARRAY = 'oauth2_storage_phalcon_config';
    protected $db;
    protected $di;
    protected $config;

    /**
     * Phalcon constructor.
     * @param \Phalcon\DiInterface $di Dependency Injector from the Phalcon Application, this is necessary for Model Lookups
     * @param array $config Config to append to the current config
     */
    public function __construct($di, $config = array())
    {
        if (!isset($di['db']))
            throw new \InvalidArgumentException('Dependency injector must contain a valid database connection');

        $config = array_merge(array(
            'client_table' => 'oauth_clients',
            'access_token_table' => 'oauth_access_tokens',
            'refresh_token_table' => 'oauth_refresh_tokens',
            'code_table' => 'oauth_authorization_codes',
            'user_table' => 'oauth_users',
            'jwt_table' => 'oauth_jwt',
            'jti_table' => 'oauth_jti',
            'scope_table' => 'oauth_scopes',
            'public_key_table' => 'oauth_public_keys',
        ), $config);

        $di->set(self::KEY_PHALCON_CONFIG_ARRAY, function () use ($config) {
            return $config;
        });

        $manager = $di->get('modelsManager');
        $manager->setDi($di);
        $di->set('modelsManager', $manager);

        $this->config = $config;
        $this->di = $di;
    }

    /**
     * @return \Phalcon\DiInterface
     */
    public function getDi()
    {
        return $this->di;
    }

    /* OAuth2\Storage\ClientCredentialsInterface */
    public function checkClientCredentials($client_id, $client_secret = null)
    {
        $client = Models\OauthClients::findFirst(
            array(
                "conditions" => "client_id = ?1",
                "bind" => array(1 => $client_id),
                "limit" => 1
            )
        );

        return $client != false && $client->client_secret == $client_secret;
    }

    public function isPublicClient($client_id)
    {
        $clients = Models\OauthClients::findFirst(
            array(
                "conditions" => "client_id = ?1",
                "bind" => array(1 => $client_id),
                "limit" => 1
            )
        );

        return empty($clients->client_secret);
    }

    public function setClientDetails($client_id, $client_secret = null, $redirect_uri = null, $grant_types = null, $scope = null, $user_id = null)
    {
        $client = new Models\OauthClients();
        $client->client_id = $client_id;

        $client->client_secret = $client_secret;
        $client->redirect_uri = $redirect_uri;
        $client->grant_types = $grant_types;
        $client->scope = $scope;
        $client->user_id = $user_id;

        return $client->save();
    }

    public function checkRestrictedGrantType($client_id, $grant_type)
    {
        $details = $this->getClientDetails($client_id);

        if (isset($details['grant_types'])) {
            $grant_types = explode(' ', $details['grant_types']);
            return in_array($grant_type, (array)$grant_types);
        }

        // if grant_types are not defined, then none are restricted
        return true;
    }

    public function getClientDetails($client_id)
    {
        $clients = Models\OauthClients::findFirst(
            array(
                "conditions" => "client_id = ?1",
                "bind" => array(1 => $client_id),
                "limit" => 1
            )
        );

        return $clients->toArray();
    }

    /* OAuth2\Storage\AccessTokenInterface */

    public function getAccessToken($access_token)
    {
        $token = Models\OauthAccessTokens::findFirst(
            array(
                "conditions" => "access_token = ?1",
                "bind" => array(1 => $access_token),
                "limit" => 1
            )
        );

        if ($token != false) {
            $tokenArray = $token->toArray();
            $tokenArray['expires'] = strtotime($token->expires);
            return $tokenArray;
        } else {
            // If token == false, then return false
            return false;
        }
    }

    public function setAccessToken($access_token, $client_id, $user_id, $expires, $scope = null)
    {
        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);

        $token = new Models\OauthAccessTokens();
        $token->access_token = $access_token;

        // Update the fields only if they are set
        $token->client_id = $client_id;
        $token->client_ip = $_SERVER['REMOTE_ADDR'];
        $token->client_useragent = $_SERVER['HTTP_USER_AGENT'];
        $token->user_id = $user_id;
        $token->expires = $expires;
        isset($scope) ?: $token->scope = $scope;

        return $token->save();
    }

    public function unsetAccessToken($access_token)
    {
        $token = Models\OauthAccessTokens::findFirst(
            array(
                "conditions" => "access_token = ?1",
                "bind" => array(1 => $access_token),
                "limit" => 1
            )
        );
        return $token->delete();
    }

    /* OAuth2\Storage\AuthorizationCodeInterface */

    public function setAuthorizationCode($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null, $id_token = null)
    {

        // Convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);

        // if it exists, update it.
        $authCode = $this->getAuthorizationCode($code);
        if ($authCode == false)
            $authCode = new Models\OauthAuthorizationCodes();

        $authCode->authorization_code = $code;
        $authCode->client_id = $client_id;
        $authCode->user_id = $user_id;
        $authCode->redirect_uri = $redirect_uri;
        $authCode->expires = $expires;

        $authCode->scope = $scope;
        $authCode->id_token = $id_token;

        return $authCode->save();
    }

    public function getAuthorizationCode($code)
    {
        $code = Models\OauthAuthorizationCodes::findFirst(
            array(
                "conditions" => "authorization_code = ?1",
                "bind" => array(1 => $code),
                "limit" => 1
            )
        );
        if ($code != false) {
            $codeArray = $code->toArray();
            $codeArray['expires'] = strtotime($code->expires);
            return $codeArray;
        } else {
            // If code == false, then return false
            return false;
        }
    }

    /**
     * @deprecated No longer used.
     * @see setAuthorizationCode.
     */
    public function setAuthorizationCodeWithIdToken($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null, $id_token = null)
    {

        // Convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);

        // if it exists, update it.
        $authCode = $this->getAuthorizationCode($code);
        if ($authCode == false)
            $authCode = new Models\OauthAuthorizationCodes();

        $authCode->authorization_code = $code;
        $authCode->client_id = $client_id;
        $authCode->user_id = $user_id;
        $authCode->redirect_uri = $redirect_uri;
        $authCode->expires = $expires;
        $authCode->id_token = $id_token;

        $authCode->scope = $scope;

        return $authCode->save();
    }


    public function expireAuthorizationCode($code)
    {
        $code = Models\OauthAuthorizationCodes::findFirst(
            array(
                "conditions" => "authorization_code = ?1",
                "bind" => array(1 => $code),
                "limit" => 1
            )
        );

        return $code->delete();
    }

    /* OAuth2\Storage\UserCredentialsInterface */
    public function checkUserCredentials($username, $password)
    {
        if ($user = $this->getUser($username)) {
            return $this->checkPassword($user, $password);
        }
        return false;
    }

    public function getUser($username)
    {
        $user = Models\OauthUsers::findFirst(
            array(
                "conditions" => "username = ?1",
                "bind" => array(1 => $username),
                "limit" => 1
            )
        );

        if ($user == false)
            return false;
        else
            return array_merge(array('user_id' => $username), $user->toArray());
    }

    /* OAuth2\Storage\UserClaimsInterface */

    protected function checkPassword($user, $password)
    {
        return $user['password'] == $this->hashPassword($password);
    }

    protected function hashPassword($password)
    {
        return sha1($password);
    }

    /* OAuth2\Storage\RefreshTokenInterface */

    public function getUserClaims($user_id, $claims)
    {
        if (!$userDetails = $this->getUserDetails($user_id)) {
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

    // use a secure hashing algorithm when storing passwords. Override this for your application

    public function getUserDetails($username)
    {
        return $this->getUser($username);
    }

    protected function getUserClaim($claim, $userDetails)
    {
        $userClaims = array();
        $claimValuesString = constant(sprintf('self::%s_CLAIM_VALUES', strtoupper($claim)));
        $claimValues = explode(' ', $claimValuesString);

        foreach ($claimValues as $value) {
            $userClaims[$value] = isset($userDetails[$value]) ? $userDetails[$value] : null;
        }

        return $userClaims;
    }

    /* OAuth2\Storage\UserCredentialsInterface */

    public function getRefreshToken($refresh_token)
    {
        $token = Models\OauthRefreshTokens::findFirst(
            array(
                "conditions" => "refresh_token = ?1",
                "bind" => array(1 => $refresh_token),
                "limit" => 1
            )
        );

        if ($token != false) {
            $tokenArray = $token->toArray();
            $tokenArray['expires'] = strtotime($token->expires);
            return $tokenArray;
        } else {
            // If token == false, then return false
            return false;
        }
    }

    public function setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope = null)
    {
        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);

        $token = new Models\OauthRefreshTokens();
        $token->refresh_token = $refresh_token;
        $token->client_id = $client_id;
        $token->user_id = $user_id;
        $token->expires = $expires;
        $token->client_ip = $_SERVER['REMOTE_ADDR'];
        $token->client_useragent = $_SERVER['HTTP_USER_AGENT'];
        $token->scope = $scope;

        return $token->save();
    }

    public function unsetRefreshToken($refresh_token)
    {
        $token = Models\OauthRefreshTokens::findFirst(
            array(
                "conditions" => "refresh_token = ?1",
                "bind" => array(1 => $refresh_token),
                "limit" => 1
            )
        );

        return $token->delete();
    }

    public function setUser($username, $password, $firstName = null, $lastName = null)
    {
        // do not store in plaintext
        $password = $this->hashPassword($password);

        // if it exists, update it.
        $user = $this->getUser($username);
        if ($user == false) {
            $user = Models\OauthUsers::findFirst(
                array(
                    "conditions" => "username = ?1",
                    "bind" => array(1 => $username),
                    "limit" => 1
                )
            );
            $user->username = $username;
        }
        $user->password = $password;
        $user->first_name = $firstName;
        $user->first_name = $lastName;

        return $user->save();
    }

    /* OAuth2\Storage\ScopeInterface */
    public function scopeExists($scope)
    {
        $scope = explode(' ', $scope);
        $whereIn = implode(',', array_fill(0, count($scope), '?'));
        $result = Models\OauthScopes::count(
            array(
                "conditions" => "scope IN(?1)",
                "bind" => array(1 => $whereIn),
                "limit" => 1
            )
        );

        return $result == count($scope);
    }

    public function getDefaultScope($client_id = null)
    {
        $scopes = Models\OauthScopes::find(
            array(
                "conditions" => "is_default = ?1",
                "bind" => array(1 => true)
            )
        );

        if (count($scopes) >= 1) {
            $defaultScope = array_map(function ($row) {
                return $row->scope;
            }, $scopes);

            return implode(' ', $defaultScope);
        }

        return null;
    }

    /* OAuth2\Storage\JWTBearerInterface */
    public function getClientKey($client_id, $subject)
    {

        $clientKey = Models\OauthJwt::findFirst(
            array(
                "conditions" => "client_id = ?1 AND subject = ?2",
                "bind" => array(1 => $client_id, 2 => $subject),
                "limit" => 1
            )
        );

        if ($clientKey != false)
            return $clientKey->public_key;
        else
            return false;
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

    public function getJti($client_id, $subject, $audience, $expires, $jti)
    {

        $result = Models\OauthJti::findFirst(
            array(
                "conditions" => "client_id = :client_id: AND subject = :subject: AND audience = :audience: AND expires = :expires: AND jti = :jti:",
                "bind" => [
                    "client_id" => $client_id,
                    "subject" => $subject,
                    "audience" => $audience,
                    "expires" => $expires,
                    "jti" => $jti
                ],
                "limit" => 1
            )
        );

        if ($result != false)
            return $result->toArray(['issuer', 'subject', 'audience', 'expires', 'jti']);
        else
            return null;
    }

    public function setJti($client_id, $subject, $audience, $expires, $jti)
    {
        $jtiModel = new Models\OauthJti();
        $jtiModel->issuer = $client_id;
        $jtiModel->subject = $subject;
        $jtiModel->audience = $audience;
        $jtiModel->expires = $expires;
        $jtiModel->jti = $jti;

        return $jtiModel->save();
    }

    /* OAuth2\Storage\PublicKeyInterface */
    public function getPublicKey($client_id = null)
    {
        $publicKey = Models\OauthPublicKeys::findFirst(
            array(
                "conditions" => "client_id = ?1 OR client_id IS NULL",
                "bind" => array(1 => $client_id),
                "limit" => 1
            )
        );

        if ($publicKey != false)
            return $publicKey->public_key;
        else
            return false;
    }

    public function getPrivateKey($client_id = null)
    {
        $publicKey = Models\OauthPublicKeys::findFirst(
            array(
                "conditions" => "client_id = ?1",
                "bind" => array(1 => $client_id),
                "limit" => 1
            )
        );

        if ($publicKey != false)
            return $publicKey->private_key;
        else
            return false;
    }

    public function getEncryptionAlgorithm($client_id = null)
    {
        $publicKey = Models\OauthPublicKeys::findFirst(
            array(
                "conditions" => "client_id = ?1",
                "bind" => array(1 => $client_id),
                "limit" => 1
            )
        );

        if ($publicKey != false)
            return $publicKey->encryption_algorithm;
        else
            return 'RS256';
    }

    /**
     * SQL to create OAuth2 tables for PDO/Phalcon storage
     *
     * @see https://github.com/dsquier/oauth2-server-php-mysql
     */
    public function getBuildSql($dbName = 'oauth2_server_php')
    {
        $sql = "
            CREATE TABLE {$this->config['client_table']} (
              `client_id` varchar(80) NOT NULL,
              `client_secret` varchar(80) DEFAULT NULL,
              `redirect_uri` varchar(2000) DEFAULT NULL,
              `grant_types` varchar(80) DEFAULT NULL,
              `scope` varchar(4000) DEFAULT NULL,
              `user_id` varchar(80) DEFAULT NULL,
              PRIMARY KEY (client_id)
            );
            
            CREATE TABLE {$this->config['access_token_table']} (
              `access_token` varchar(40) NOT NULL,
              `valid` tinyint(1) NOT NULL DEFAULT '1',
              `client_ip` varchar(155) NOT NULL,
              `client_useragent` text NOT NULL,
              `client_id` varchar(80) NOT NULL,
              `user_id` varchar(80) DEFAULT NULL,
              `expires` timestamp NOT NULL,
              `scope` varchar(4000) DEFAULT NULL
              PRIMARY KEY (access_token)
            );
            
            CREATE TABLE {$this->config['code_table']} (
              `authorization_code` varchar(40) NOT NULL,
              `client_id` varchar(80) NOT NULL,
              `user_id` varchar(80) DEFAULT NULL,
              `redirect_uri` varchar(2000) DEFAULT NULL,
              `expires` timestamp NOT NULL,
              `scope` varchar(4000) DEFAULT NULL,
              `id_token` varchar(1000) DEFAULT NULL,
              PRIMARY KEY (authorization_code)
            );
            
            CREATE TABLE {$this->config['refresh_token_table']} (
              `refresh_token` varchar(40) NOT NULL,
              `valid` tinyint(1) NOT NULL DEFAULT '1',
              `client_id` varchar(80) NOT NULL,
              `user_id` varchar(80) DEFAULT NULL,
              `client_ip` varchar(155) NOT NULL,
              `client_useragent` text NOT NULL,
              `expires` timestamp NOT NULL,
              `scope` varchar(4000) DEFAULT NULL,
              PRIMARY KEY (refresh_token)
            );
            
            CREATE TABLE {$this->config['user_table']} (
              `id` bigint(20) NOT NULL AUTO_INCREMENT,
              `status` tinyint(2) NOT NULL DEFAULT '0',
              `username` varchar(80) NOT NULL DEFAULT '',
              `password` varchar(80) DEFAULT NULL,
              `first_name` varchar(80) DEFAULT NULL,
              `last_name` varchar(80) DEFAULT NULL,
              `email` varchar(80) DEFAULT NULL,
              `email_verified` tinyint(1) DEFAULT NULL,
              `scope` varchar(4000) DEFAULT NULL,
              PRIMARY KEY (id)
            );
            
            CREATE TABLE {$this->config['scope_table']} (
              `scope` varchar(80) NOT NULL,
              `is_default` tinyint(1) DEFAULT NULL,
              PRIMARY KEY (scope)
            );
            
            CREATE TABLE {$this->config['jwt_table']} (
              `client_id` varchar(80) NOT NULL,
              `subject` varchar(80) DEFAULT NULL,
              `public_key` varchar(2000) NOT NULL
            );
            
            CREATE TABLE {$this->config['jti_table']} (
              `issuer` varchar(80) NOT NULL,
              `subject` varchar(80) DEFAULT NULL,
              `audience` varchar(80) DEFAULT NULL,
              `expires` timestamp NOT NULL,
              `jti` varchar(2000) NOT NULL
            );
            
            CREATE TABLE {$this->config['public_key_table']} (
              `client_id` varchar(80) DEFAULT NULL,
              `public_key` varchar(2000) DEFAULT NULL,
              `private_key` varchar(2000) DEFAULT NULL,
              `encryption_algorithm` varchar(100) DEFAULT 'RS256'
            );
        ";

        return $sql;
    }

}