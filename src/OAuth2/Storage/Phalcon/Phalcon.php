<?php

namespace OAuth2\Storage;

use OAuth2\OpenID\Storage\AuthorizationCodeInterface as OpenIDAuthorizationCodeInterface;
use OAuth2\OpenID\Storage\UserClaimsInterface;
use OAuth2\Storage\Models;
use Phalcon\Di;
use Phalcon\Mvc\Model;

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
    protected $db;
    protected $config;

    /**
     * Phalcon constructor.
     * @param \Phalcon\DiInterface $di Dependency Injector from the Phalcon Application, this is necessary for Model Lookups
     * @param array $config Config to append to the current config
     */
    public function __construct($di, $config = array())
    {
        $this->di = $di;
        $this->config = array_merge(array(
            'client_table' => 'oauth__clients',
            'access_token_table' => 'oauth__access_tokens',
            'refresh_token_table' => 'oauth__refresh_tokens',
            'code_table' => 'oauth__authorization_codes',
            'user_table' => 'oauth__users',
            'jwt_table' => 'oauth__jwt',
            'jti_table' => 'oauth__jti',
            'scope_table' => 'oauth__scopes',
            'public_key_table' => 'oauth__public_keys',
        ), $config);
    }

    /**
     * @param $client_id
     * @param null $client_secret
     * @return bool
     */
    public function checkClientCredentials($client_id, $client_secret = null)
    {
        $clients = Models\OauthClients::findFirst(
            array(
                "conditions" => "client_id = ?1 AND client_secret = ?2",
                "bind" => array(1 => $client_id, 2 => $client_secret),
                "limit" => 1
            )
        );

        return $clients != false;
    }

    /**
     * @param $client_id
     * @return bool
     */
    public function isPublicClient($client_id)
    {
        $clients = Models\OauthClients::findFirst(
            array(
                "conditions" => "client_id = ?1",
                "bind" => array(1 => $client_id),
                "limit" => 1
            )
        );

        return empty($clients['client_secret']);
    }

    /**
     * @param $client_id
     * @param null $client_secret
     * @param null $redirect_uri
     * @param null $grant_types
     * @param null $scope
     * @param null $user_id
     * @return mixed
     */
    public function setClientDetails($client_id, $client_secret = null, $redirect_uri = null, $grant_types = null, $scope = null, $user_id = null)
    {
        $client = new Models\OauthClients();
        $client->client_id = $client_id;

        // Update the fields only if they are set
        isset($client_secret) ?: $client->client_secret = $client_secret;
        isset($redirect_uri) ?: $client->redirect_uri = $redirect_uri;
        isset($grant_types) ?: $client->grant_types = $grant_types;
        isset($scope) ?: $client->scope = $scope;
        isset($user_id) ?: $client->user_id = $user_id;

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

    /**
     * @param $client_id
     * @return array
     */
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
        if ($token->count() == 1) {
            $token['expires'] = strtotime($token['expires']);
        }

        return $token;
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
    public function getAuthorizationCode($code)
    {
        $code = Models\OauthAuthorizationCodes::findFirst(
            array(
                "conditions" => "authorization_code = ?1",
                "bind" => array(1 => $code),
                "limit" => 1
            )
        );
        if ($code->count() == 1) {
            $code['expires'] = strtotime($code['expires']);
        }
        return $code;
    }

    public function setAuthorizationCode($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null, $id_token = null)
    {
        // Convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);

        $authCode = new Models\OauthAuthorizationCodes();
        $authCode->authorization_code = $code;
        $authCode->client_id = $client_id;
        $authCode->user_id = $user_id;
        $authCode->redirect_uri = $redirect_uri;
        $authCode->expires = $expires;

        // Update the fields only if they are set
        isset($scope) ?: $authCode->scope = $scope;
        isset($id_token) ?: $authCode->id_token = $id_token;

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

        if ($user == false) {
            return false;
        }

        return array_merge(array('user_id' => $username), $user->toArray());
    }

    /* UserClaimsInterface */

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

    // plaintext passwords are bad!  Override this for your application

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
            // convert expires to epoch time
            $token->expires = strtotime($token->expires);
        }

        return $token->toArray();
    }

    // use a secure hashing algorithm when storing passwords. Override this for your application

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
        isset($scope) ?: $token->scope = $scope;

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

        $user = Models\OauthUsers::findFirst(
            array(
                "conditions" => "username = ?1",
                "bind" => array(1 => $username),
                "limit" => 1
            )
        );

        $user->password = $password;

        // Update values only if set
        isset($firstName) ?: $user->first_name = $firstName;
        isset($lastName) ?: $user->first_name = $lastName;

        return $user->save();
    }


    /* JWTBearerInterface */
    public function getClientKey($client_id, $subject)
    {

        $clientKey = Models\OauthJwt::findFirst(
            array(
                "conditions" => "client_id = ?1 AND subject = ?2",
                "bind" => array(1 => $client_id, 2 => $subject),
                "limit" => 1
            )
        );

        return $clientKey->count() == 1 ? $clientKey->client_id : false;
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

    /**
     * Check if the provided scope exists.
     *
     * @param $scope
     * A space-separated string of scopes.
     *
     * @return boolean
     * TRUE if it exists, FALSE otherwise.
     */
    public function scopeExists($scope)
    {
        $scopeRow = Models\OauthScopes::findFirst(
            array(
                "conditions" => "scope = ?1",
                "bind" => array(1 => $scope),
                "limit" => 1
            )
        );

        return $scopeRow == 1;
    }

    /**
     * The default scope to use in the event the client
     * does not request one. By returning "false", a
     * request_error is returned by the server to force a
     * scope request by the client. By returning "null",
     * opt out of requiring scopes
     *
     * @param $client_id
     * An optional client id that can be used to return customized default scopes.
     *
     * @return
     * string representation of default scope, null if
     * scopes are not defined, or false to force scope
     * request by the client
     *
     * ex:
     *     'default'
     * ex:
     *     null
     */
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

    public function getJti($client_id, $subject, $audience, $expires, $jti)
    {

        $result = Models\OauthJti::findFirst(
            array(
                "conditions" => "client_id = :client_id: AND subject = :subject: AND audience = :audience: AND expires = :expires: AND jti = :jti:",
                "bind" => array(
                    "client_id" => $client_id,
                    "subject" => $subject,
                    "audience" => $audience,
                    "expires" => $expires,
                    "jti" => $jti
                ),
                "limit" => 1
            )
        );

        if ($result->count() == 1) {
            $result = $result->toArray();
            return array(
                'issuer' => $result['issuer'],
                'subject' => $result['subject'],
                'audience' => $result['audience'],
                'expires' => $result['expires'],
                'jti' => $result['jti'],
            );
        }

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

    /* PublicKeyInterface */
    public function getPublicKey($client_id = null)
    {
        $publicKey = Models\OauthPublicKeys::findFirst(
            array(
                "conditions" => "client_id = ?1",
                "bind" => array(1 => $client_id),
                "limit" => 1
            )
        );

        if ($array = $publicKey->toArray())
            return $array['public_key'];
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

        if ($array = $publicKey->toArray())
            return $array['private_key'];
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

        if ($array = $publicKey->toArray())
            return $array['encryption_algorithm'];
        else
            return 'RS256';
    }

    /**
     * DDL to create OAuth2 database and tables for PDO/Phalcon storage
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
              `scope` varchar(4000) DEFAULT NULL
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
