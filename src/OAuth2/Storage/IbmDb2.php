<?php

namespace OAuth2\Storage;

use OAuth2\OpenID\Storage\UserClaimsInterface;
use OAuth2\OpenID\Storage\AuthorizationCodeInterface as OpenIDAuthorizationCodeInterface;

/**
 *
 * NOTE: This class is meant to get users started
 * quickly. If your application requires further
 * customization, extend this class or create your own.
 *
 * NOTE: Passwords are stored in plaintext, which is never
 * a good idea.  Be sure to override this for your application
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 * @author Alan Seiden <alan at alanseiden dot com>
 */
class IbmDb2 implements
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

    public function __construct($connection, $config = array())
    {
        if (!is_resource($connection)) {
            // Note: Unlike PDO, IbmDb2 (ibm_db2 extension) cannot be configured via dsn string.

            if (!is_array($connection)) {
                throw new \InvalidArgumentException('First argument to OAuth2\Storage\IbmDb2 must be a resource or a configuration array');
            }

            // merge optional parameters. Set empty defaults if not present in $connection array.
            $connection = array_merge(array(
                'database' =>     '',
                'username' =>   '',
                'password' =>   '',
                'persistent' => false,
                'driver_options' =>    array(),
            ), $connection);

            // use persistent or not
            $isPersistent = $connection['persistent'];
            $connectFunction = ((bool) $isPersistent) ? 'db2_pconnect' : 'db2_connect';

            // try to connect
            $connection = $connectFunction($connection['database'], $connection['username'], $connection['password'], $connection['driver_options']);

            // this is how ZF2 handles connection errors
            if ($connection === false) {
                throw new Exception\RuntimeException(sprintf(
                    '%s: Unable to connect to database',
                    __METHOD__
                ));
            }

        }

        $this->db = $connection;

        $this->config = array_merge(array(
            'client_table' => 'oauth_clients',
            'access_token_table' => 'oauth_access_tokens',
            'refresh_token_table' => 'oauth_refresh_tokens',
            'code_table' => 'oauth_authorization_codes',
            'user_table' => 'oauth_users',
            'jwt_table'  => 'oauth_jwt',
            'jti_table'  => 'oauth_jti',
            'scope_table'  => 'oauth_scopes',
            'public_key_table'  => 'oauth_public_keys',
        ), $config);
    }

    /* OAuth2\Storage\ClientCredentialsInterface */
    public function checkClientCredentials($client_id, $client_secret = null)
    {
        $stmt = db2_prepare($this->db, sprintf('SELECT * from %s where client_id = ?', $this->config['client_table']));
        $successfulExecute = db2_execute($stmt, compact('client_id'));
        $result = db2_fetch_assoc($stmt);

        // make this extensible
        return $result && $result['client_secret'] == $client_secret;
    }

    public function isPublicClient($client_id)
    {
        $stmt = db2_prepare($this->db, sprintf('SELECT * from %s where client_id = ?', $this->config['client_table']));
        $successfulExecute = db2_execute($stmt, compact('client_id'));

        if (!$result = db2_fetch_assoc($stmt)) {
            return false;
        }

        return empty($result['client_secret']);
    }

    /* OAuth2\Storage\ClientInterface */
    public function getClientDetails($client_id)
    {
        $stmt = db2_prepare($this->db, sprintf('SELECT * from %s where client_id = ?', $this->config['client_table']));
        $successfulExecute = db2_execute($stmt, compact('client_id'));

        return db2_fetch_assoc($stmt);
    }

    public function setClientDetails($client_id, $client_secret = null, $redirect_uri = null, $grant_types = null, $scope = null, $user_id = null)
    {
        // if it exists, update it.
        if ($this->getClientDetails($client_id)) {
            $stmt = db2_prepare($this->db, $sql = sprintf('UPDATE %s SET client_secret=?, redirect_uri=?, grant_types=?, scope=?, user_id=? where client_id=?', $this->config['client_table']));
            return db2_execute($stmt, compact('client_secret', 'redirect_uri', 'grant_types', 'scope', 'user_id', 'client_id'));
        } else {
            $stmt = db2_prepare($this->db, sprintf('INSERT INTO %s (client_id, client_secret, redirect_uri, grant_types, scope, user_id) VALUES (?, ?, ?, ?, ?, ?)', $this->config['client_table']));
            return db2_execute($stmt, compact('client_id', 'client_secret', 'redirect_uri', 'grant_types', 'scope', 'user_id'));
            
        }

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

    /* OAuth2\Storage\AccessTokenInterface */
    public function getAccessToken($access_token)
    {
        $stmt = db2_prepare($this->db, sprintf('SELECT * from %s where access_token = ?', $this->config['access_token_table']));

        $token = db2_execute($stmt, compact('access_token'));

        if ($token = db2_fetch_assoc($stmt)) {
            
            // db2 timestamps look like yyyy-mm-dd-hh.mm.ss.000000 where the last six are microseconds.
            // replace 10th character (dash between day and time) with a space to make it intelligible to strtotime()
            $token['expires'] = substr_replace($token['expires'], ' ', 10, 1);
	        // convert date string back to Unix timestamp
            $token['expires'] = strtotime($token['expires']);
        }

        return $token;
    }

    public function setAccessToken($access_token, $client_id, $user_id, $expires, $scope = null)
    {
        // convert expires to datestring
        $expires = date("Y-m-d-H.i.s", $expires);

        // if it exists, update it.
        if ($this->getAccessToken($access_token)) {
            $stmt = db2_prepare($this->db, sprintf('UPDATE %s SET client_id=?, expires=?, user_id=?, scope=? where access_token=?', $this->config['access_token_table']));
            if (false == $stmt) {
                throw new \Exception(db2_stmt_errormsg());
            }
            $executeSuccess = db2_execute($stmt, compact('client_id', 'expires', 'user_id', 'scope', 'access_token'));
        } else {
            $stmt = db2_prepare($this->db, sprintf('INSERT INTO %s (access_token, client_id, expires, user_id, scope) VALUES (?, ?, ?, ?, ?)', $this->config['access_token_table']));
            if (false == $stmt) {
                throw new \Exception(db2_stmt_errormsg());
            }
            $executeSuccess = db2_execute($stmt, compact('access_token', 'client_id', 'expires', 'user_id', 'scope'));
        }

        if (false == $executeSuccess) {
            throw new \Exception(db2_stmt_errormsg());
        }

    }

    /* OAuth2\Storage\AuthorizationCodeInterface */
    public function getAuthorizationCode($code)
    {
        $stmt = db2_prepare($this->db, sprintf('SELECT * from %s where authorization_code = ?', $this->config['code_table']));
        $successfulExecute = db2_execute($stmt, compact('client_id'));

        if ($code = db2_fetch_assoc($stmt)) {
            // db2 timestamps look like yyyy-mm-dd-hh.mm.ss.000000 where the last six are microseconds.
            // replace 10th character (dash between day and time) with a space to make it intelligible to strtotime()
            $code['expires'] = substr_replace($code['expires'], ' ', 10, 1);
	        // convert date string back to Unix timestamp
            $code['expires'] = strtotime($code['expires']);
        }

        return $code;
    }

    public function setAuthorizationCode($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null, $id_token = null)
    {
        if (func_num_args() > 6) {
            // we are calling with an id token
            return call_user_func_array(array($this, 'setAuthorizationCodeWithIdToken'), func_get_args());
        }

        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);

        // if it exists, update it.
        if ($this->getAuthorizationCode($code)) {
            $stmt = db2_prepare($this->db, $sql = sprintf('UPDATE %s SET client_id=?, user_id=?, redirect_uri=?, expires=?, scope=? where authorization_code=?', $this->config['code_table']));
            return db2_execute($stmt, compact('client_id', 'user_id', 'redirect_uri', 'expires', 'scope', 'code'));
        } else {
            $stmt = db2_prepare($this->db, sprintf('INSERT INTO %s (authorization_code, client_id, user_id, redirect_uri, expires, scope) VALUES (?, ?, ?, ?, ?, ?)', $this->config['code_table']));
            return db2_execute($stmt, compact('code', 'client_id', 'user_id', 'redirect_uri', 'expires', 'scope'));
            
        }

    }

    private function setAuthorizationCodeWithIdToken($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null, $id_token = null)
    {
        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);

        // if it exists, update it.
        if ($this->getAuthorizationCode($code)) {
            $stmt = db2_prepare($this->db, $sql = sprintf('UPDATE %s SET client_id=?, user_id=?, redirect_uri=?, expires=?, scope=?, id_token =? where authorization_code=?', $this->config['code_table']));
            return db2_execute($stmt, compact('client_id', 'user_id', 'redirect_uri', 'expires', 'scope', 'id_token', 'code'));
            
        } else {
            $stmt = db2_prepare($this->db, sprintf('INSERT INTO %s (authorization_code, client_id, user_id, redirect_uri, expires, scope, id_token) VALUES (?, ?, ?, ?, ?, ?, ?)', $this->config['code_table']));
            return db2_execute($stmt, compact('code', 'client_id', 'user_id', 'redirect_uri', 'expires', 'scope', 'id_token'));
            
        }

    }

    public function expireAuthorizationCode($code)
    {
        $stmt = db2_prepare($this->db, sprintf('DELETE FROM %s WHERE authorization_code = ?', $this->config['code_table']));

        return db2_execute($stmt, compact('code'));

    }

    /* OAuth2\Storage\UserCredentialsInterface */
    public function checkUserCredentials($username, $password)
    {
        if ($user = $this->getUser($username)) {
            return $this->checkPassword($user, $password);
        }

        return false;
    }

    public function getUserDetails($username)
    {
        return $this->getUser($username);
    }

    /* UserClaimsInterface */
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

    /* OAuth2\Storage\RefreshTokenInterface */
    public function getRefreshToken($refresh_token)
    {
        $stmt = db2_prepare($this->db, sprintf('SELECT * FROM %s WHERE refresh_token = ?', $this->config['refresh_token_table']));

        $token = db2_execute($stmt, compact('refresh_token'));
        if ($token = db2_fetch_assoc($stmt)) {
            // convert expires to epoch time
            $token['expires'] = strtotime($token['expires']);
        }

        return $token;
    }

    public function setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope = null)
    {
        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);

        $stmt = db2_prepare($this->db, sprintf('INSERT INTO %s (refresh_token, client_id, user_id, expires, scope) VALUES (?, ?, ?, ?, ?)', $this->config['refresh_token_table']));

        return db2_execute($stmt, compact('refresh_token', 'client_id', 'user_id', 'expires', 'scope'));
    }

    public function unsetRefreshToken($refresh_token)
    {
        $stmt = db2_prepare($this->db, sprintf('DELETE FROM %s WHERE refresh_token = ?', $this->config['refresh_token_table']));

        return db2_execute($stmt, compact('refresh_token'));
    }

    // plaintext passwords are bad!  Override this for your application
    protected function checkPassword($user, $password)
    {
        return $user['password'] == sha1($password);
    }

    public function getUser($username)
    {
        $stmt = db2_prepare($this->db, $sql = sprintf('SELECT * from %s where username=?', $this->config['user_table']));
        $successfulExecute = db2_execute($stmt, array('username' => $username));

        if (!$userInfo = db2_fetch_assoc($stmt)) {
            return false;
        }

        // the default behavior is to use "username" as the user_id
        return array_merge(array(
            'user_id' => $username
        ), $userInfo);
    }

    public function setUser($username, $password, $firstName = null, $lastName = null)
    {
        // do not store in plaintext
        $password = sha1($password);

        // if it exists, update it.
        if ($this->getUser($username)) {
            $stmt = db2_prepare($this->db, $sql = sprintf('UPDATE %s SET password=?, first_name=?, last_name=? where username=?', $this->config['user_table']));
            return db2_execute($stmt, compact('password', 'firstName', 'lastName', 'username'));
        } else {
            $stmt = db2_prepare($this->db, sprintf('INSERT INTO %s (username, password, first_name, last_name) VALUES (?, ?, ?, ?)', $this->config['user_table']));
            return db2_execute($stmt, compact('username', 'password', 'firstName', 'lastName'));
            
        }

    }

    /* ScopeInterface */
    public function scopeExists($scope)
    {
        $scope = explode(' ', $scope);
        $whereIn = implode(',', array_fill(0, count($scope), '?'));
        $stmt = db2_prepare($this->db, sprintf('SELECT count(scope) as count FROM %s WHERE scope IN (%s)', $this->config['scope_table'], $whereIn));
        $successfulExecute = db2_execute($stmt, $scope);

        if ($result = db2_fetch_assoc($stmt)) {
            return $result['count'] == count($scope);
        }

        return false;
    }

    public function getDefaultScope($client_id = null)
    {
        $stmt = db2_prepare($this->db, sprintf('SELECT scope FROM %s WHERE is_default=?', $this->config['scope_table']));
        $successfulExecute = db2_execute($stmt, array('is_default' => true));


        $result = false;
        // was fetchAll()
        $result = db2_fetch_assoc($stmt);

        if ($result) {
            $defaultScope = array_map(function ($row) {
                return $row['scope'];
            }, $result);

            return implode(' ', $defaultScope);
        }

        return null;
    }

    /* JWTBearerInterface */
    public function getClientKey($client_id, $subject)
    {
        $stmt = db2_prepare($this->db, $sql = sprintf('SELECT public_key from %s where client_id=? AND subject=?', $this->config['jwt_table']));

        $successfulExecute = db2_execute($stmt, array('client_id' => $client_id, 'subject' => $subject));

        return $stmt->fetchColumn();
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
        $stmt = db2_prepare($this->db, $sql = sprintf('SELECT * FROM %s WHERE issuer=? AND subject=? AND audience=? AND expires=? AND jti=?', $this->config['jti_table']));

        $successfulExecute = db2_execute($stmt, compact('client_id', 'subject', 'audience', 'expires', 'jti'));

        if ($result = db2_fetch_assoc($stmt)) {
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
        $stmt = db2_prepare($this->db, sprintf('INSERT INTO %s (issuer, subject, audience, expires, jti) VALUES (?, ?, ?, ?, ?)', $this->config['jti_table']));

        return db2_execute($stmt, compact('client_id', 'subject', 'audience', 'expires', 'jti'));
    }

    /* PublicKeyInterface */
    public function getPublicKey($client_id = null)
    {
        $stmt = db2_prepare($this->db, $sql = sprintf('SELECT public_key FROM %s WHERE client_id=? OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC', $this->config['public_key_table']));

        $successfulExecute = db2_execute($stmt, compact('client_id'));
        if ($result = db2_fetch_assoc($stmt)) {
            return $result['public_key'];
        }
    }

    public function getPrivateKey($client_id = null)
    {
        $stmt = db2_prepare($this->db, $sql = sprintf('SELECT private_key FROM %s WHERE client_id=? OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC', $this->config['public_key_table']));

        $successfulExecute = db2_execute($stmt, compact('client_id'));
        if ($result = db2_fetch_assoc($stmt)) {
            return $result['private_key'];
        }
    }

    public function getEncryptionAlgorithm($client_id = null)
    {
        $stmt = db2_prepare($this->db, $sql = sprintf('SELECT encryption_algorithm FROM %s WHERE client_id=? OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC', $this->config['public_key_table']));

        $successfulExecute = db2_execute($stmt, compact('client_id'));
        if ($result = db2_fetch_assoc($stmt)) {
            return $result['encryption_algorithm'];
        }

        return 'RS256';
    }

    /**
     * DDL to create OAuth2 database and tables for IbmDb2 storage
     * @see https://github.com/dsquier/oauth2-server-php-mysql
     * 
     * Notes for IbmDb2 version:
     *     1. The syntax "for system name SHORTNAME" applies only to IBM i systems at 7.1 with recent PTFs applied, or later releases.
     *         It creates the specified short name for access from system utilities, RPG, etc.
     *     2.  For ease in handling lower-case column names in PHP, consider using DB2_CASE_LOWER in your connection options.
     *         http://php.net/manual/en/function.db2-connect.php
     *         $db = db2_connect('DATABASE', 'USER', 'PASSWORD', array('DB2_ATTR_CASE'=>DB2_CASE_LOWER));
     *
     */
    public function getBuildSql($dbName = 'oauth2_server_php')
    {
        $sql = "
        CREATE TABLE {$this->config['client_table']} 
          for system name OAUTHCLI        
        (
          client_id             VARCHAR(80)   NOT NULL,
          client_secret         VARCHAR(80)   NOT NULL,
          redirect_uri          VARCHAR(2000),
          grant_types           VARCHAR(80),
          scope                 VARCHAR(4000),
          user_id               VARCHAR(80),
          CONSTRAINT clients_client_id_pk PRIMARY KEY (client_id)
        )

        CREATE TABLE {$this->config['access_token_table']} 
          for system name OAUTHTOKEN
        (
          access_token         VARCHAR(40)    NOT NULL,
          client_id            VARCHAR(80)    NOT NULL,
          user_id              VARCHAR(80),
          expires              TIMESTAMP      NOT NULL,
          scope                VARCHAR(4000),
          CONSTRAINT access_token_pk PRIMARY KEY (access_token)
        )

        CREATE TABLE {$this->config['code_table']} 
          for system name OAUTHCODES
		(
          authorization_code  VARCHAR(40)    NOT NULL,
          client_id           VARCHAR(80)    NOT NULL,
          user_id             VARCHAR(80),
          redirect_uri        VARCHAR(2000),
          expires             TIMESTAMP      NOT NULL,
          scope               VARCHAR(4000),
          id_token            VARCHAR(1000),
          CONSTRAINT auth_code_pk PRIMARY KEY (authorization_code)
        )

        CREATE TABLE {$this->config['refresh_token_table']}
	      for system name OAUTHREFTK
	    (
	      refresh_token       VARCHAR(40)    NOT NULL,
          client_id           VARCHAR(80)    NOT NULL,
          user_id             VARCHAR(80),
          expires             TIMESTAMP      NOT NULL,
          scope               VARCHAR(4000),
          CONSTRAINT refresh_token_pk PRIMARY KEY (refresh_token)
        )

        CREATE TABLE {$this->config['user_table']}
	      for system name OAUTHUSERS
	    (
          username            VARCHAR(80),
          password            VARCHAR(80),
          first_name          VARCHAR(80),
          last_name           VARCHAR(80),
          email               VARCHAR(80),
          email_verified      BOOLEAN,
          scope               VARCHAR(4000)
          CONSTRAINT username_pk PRIMARY KEY (username)
        )

        CREATE TABLE {$this->config['scope_table']} 
	      for system name OAUTHSCOPE
	    (
          scope               VARCHAR(80)  NOT NULL,
          is_default          BOOLEAN,
          CONSTRAINT scope_pk PRIMARY KEY (scope)
        )

        CREATE TABLE {$this->config['jwt_table']} (
          client_id           VARCHAR(80)   NOT NULL,
          subject             VARCHAR(80),
          public_key          VARCHAR(2000) NOT NULL
        )

        CREATE TABLE {$this->config['jti_table']} (
          issuer              VARCHAR(80)   NOT NULL,
          subject             VARCHAR(80),
          audiance            VARCHAR(80),
          expires             TIMESTAMP     NOT NULL,
          jti                 VARCHAR(2000) NOT NULL
        )

        CREATE TABLE {$this->config['public_key_table']} 
          for system name OAUTHPUBKY
        (
          client_id            VARCHAR(80),
          public_key           VARCHAR(2000),
          private_key          VARCHAR(2000),
          encryption_algorithm VARCHAR(100) DEFAULT 'RS256'
        )
";

        return $sql;
    }
}
