<?php

namespace OAuth2\Storage;

use OAuth2\OpenID\Storage\UserClaimsInterface;
use OAuth2\OpenID\Storage\AuthorizationCodeInterface as OpenIDAuthorizationCodeInterface;

/**
 * Simple PDO storage for all storage types
 *
 * NOTE: This class is meant to get users started
 * quickly. If your application requires further
 * customization, extend this class or create your own.
 *
 * NOTE: Passwords are stored in plaintext, which is never
 * a good idea.  Be sure to override this for your application
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
class Oracle implements
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

    public function __construct($connection, $config = array()){
        if (!is_resource($connection)) {
            if (is_string($connection)) {
                $connection = array('dsn' => $connection);
            }
            if (!is_array($connection)) {
                throw new \InvalidArgumentException('First argument to OAuth2\Storage\Oracle must be an OCI8 connection resource, a DSN string, or a configuration array');
            }
            if (!isset($connection['dsn'])) {
                throw new \InvalidArgumentException('configuration array must contain "dsn"');
            }
            // merge optional parameters
            $connection = array_merge(array(
                'username' => null,
                'password' => null,
                'options' => array(),
            ), $connection);
            $connection = oci_connect($connection['username'], $connection['password'],$connection['dsn'], 'WE8ISO8859P1');
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
    public function checkClientCredentials($client_id, $client_secret = null){
        $stmt = oci_parse($this->db, sprintf('SELECT * from %s where client_id = :client_id', $this->config['client_table']));
        oci_bind_by_name($stmt,':client_id',$client_id);
        oci_execute($stmt);
        $result = @array_change_key_case(oci_fetch_assoc($stmt),CASE_LOWER);
        return $result && $result['client_secret'] == $client_secret;
    }


    public function isPublicClient($client_id){
        $stmt = oci_parse($this->db, sprintf('SELECT * from %s where client_id = :client_id', $this->config['client_table']));
        oci_bind_by_name($stmt,':client_id',$client_id);
        oci_execute($stmt);
        $result = oci_fetch_assoc($stmt);
        if (!$result = @array_change_key_case(oci_fetch_assoc($stmt),CASE_LOWER)) {
            return false;
        }
        return empty($result['client_secret']);
    }


    /* OAuth2\Storage\ClientInterface */
    public function getClientDetails($client_id){
        $stmt = oci_parse($this->db, sprintf('SELECT * from %s where client_id = :client_id', $this->config['client_table']));
        oci_bind_by_name($stmt,':client_id',$client_id);
        oci_execute($stmt);
        $result = @array_change_key_case(oci_fetch_assoc($stmt),CASE_LOWER);
        return $result;
    }


    public function setClientDetails($client_id, $client_secret = null, $redirect_uri = null, $grant_types = null, $scope = null, $user_id = null){
        // if it exists, update it.
        if ($this->getClientDetails($client_id)) {
            $stmt = oci_parse($this->db, $sql = sprintf('UPDATE %s SET client_secret=:client_secret, redirect_uri=:redirect_uri, grant_types=:grant_types, scope=:scope, user_id=:user_id where client_id=:client_id', $this->config['client_table']));
        } else {
            $stmt = oci_parse($this->db, sprintf('INSERT INTO %s (client_id, client_secret, redirect_uri, grant_types, scope, user_id) VALUES (:client_id, :client_secret, :redirect_uri, :grant_types, :scope, :user_id)', $this->config['client_table']));
        }

        oci_bind_by_name($stmt,':client_id',$client_id);
        oci_bind_by_name($stmt,':client_secret',$client_secret);
        oci_bind_by_name($stmt,':redirect_uri',$redirect_uri);
        oci_bind_by_name($stmt,':grant_types',$grant_types);
        oci_bind_by_name($stmt,':scope',$scope);
        oci_bind_by_name($stmt,':user_id',$user_id);
        if(!oci_execute($stmt)){
        	print_r(oci_error($stmt));
        	return false;
        }
        return true;
    }


    public function checkRestrictedGrantType($client_id, $grant_type){
        $details = $this->getClientDetails($client_id);
        if (isset($details['grant_types'])) {
            $grant_types = explode(' ', $details['grant_types']);

            return in_array($grant_type, (array) $grant_types);
        }
        // if grant_types are not defined, then none are restricted
        return true;
    }



    /* OAuth2\Storage\AccessTokenInterface */
    public function getAccessToken($access_token){
        $stmt = oci_parse($this->db, sprintf('SELECT * from %s where access_token = :access_token', $this->config['access_token_table']));
        oci_bind_by_name($stmt,':access_token',$access_token);
        oci_execute($stmt);
        if ($token = @array_change_key_case(oci_fetch_assoc($stmt),CASE_LOWER)) {
            // convert date string back to timestamp
            $token['expires'] = strtotime($token['expires']);
        }
        return $token;
    }



    public function setAccessToken($access_token, $client_id, $user_id, $expires, $scope = null){
        // convert expires to datestring

        $expires = date('Y-m-d H:i:s', $expires);
        // if it exists, update it.
        if ($this->getAccessToken($access_token)) {
        	$strSql = sprintf('UPDATE %s SET client_id=:client_id, expires=:expires, user_id=:user_id, scope=:scope where access_token=:access_token', $this->config['access_token_table']);
            $stmt = oci_parse($this->db, $strSql);
        } else {
        	$strSql = sprintf('INSERT INTO %s (access_token, client_id, expires, user_id, scope) VALUES (:access_token, :client_id, :expires, :user_id, :scope)',$this->config['access_token_table']);
            $stmt = oci_parse($this->db,$strSql);
        }


        oci_bind_by_name($stmt,':access_token',$access_token);
        oci_bind_by_name($stmt,':client_id',$client_id);
        oci_bind_by_name($stmt,':user_id',$user_id);
        oci_bind_by_name($stmt,':expires',$expires);
        oci_bind_by_name($stmt,':scope',$scope);

        if(oci_execute($stmt)){
        	 return true;
        }
        print_r(oci_error($stmt));
        return false;


    }

    public function unsetAccessToken($access_token){
        $stmt = oci_parse($this->db, sprintf('DELETE FROM %s WHERE access_token = :access_token', $this->config['access_token_table']));
        oci_bind_by_name($stmt,':access_token',$access_token);
        return  oci_execute($stmt);
    }

    /* OAuth2\Storage\AuthorizationCodeInterface */
    public function getAuthorizationCode($code){
        $stmt = oci_parse($this->db, sprintf('SELECT * from %s where authorization_code = :code', $this->config['code_table']));
        oci_bind_by_name($stmt,':code',$code);
        oci_execute($stmt);

        if ($code = @array_change_key_case(oci_fetch_assoc($stmt),CASE_LOWER)) {
            // convert date string back to timestamp
            $code['expires'] = strtotime($code['expires']);
        }
        return $code;
    }

    public function setAuthorizationCode($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null, $id_token = null){
        if (func_num_args() > 6) {
            // we are calling with an id token
            return call_user_func_array(array($this, 'setAuthorizationCodeWithIdToken'), func_get_args());
        }
        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);

        // if it exists, update it.
        if ($this->getAuthorizationCode($code)) {
            $stmt = oci_parse($this->db, $sql = sprintf('UPDATE %s SET client_id=:client_id, user_id=:user_id, redirect_uri=:redirect_uri, expires=:expires, scope=:scope where authorization_code=:code', $this->config['code_table']));
        } else {
            $stmt = oci_parse($this->db, sprintf('INSERT INTO %s (authorization_code, client_id, user_id, redirect_uri, expires, scope) VALUES (:code, :client_id, :user_id, :redirect_uri, :expires, :scope)', $this->config['code_table']));
        }

        oci_bind_by_name($stmt,':code',$code);
        oci_bind_by_name($stmt,':client_id',$client_id);
        oci_bind_by_name($stmt,':user_id',$user_id);
        oci_bind_by_name($stmt,':redirect_uri',$redirect_uri);
        oci_bind_by_name($stmt,':expires',$expires);
        oci_bind_by_name($stmt,':scope',$scope);
		if(!oci_execute($stmt)){
			print_r(oci_error($stmt));
			return false;
		}
        return true;
    }

    private function setAuthorizationCodeWithIdToken($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null, $id_token = null){
        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);

        // if it exists, update it.
        if ($this->getAuthorizationCode($code)) {
            $stmt = oci_parse($this->db, $sql = sprintf('UPDATE %s SET client_id=:client_id, user_id=:user_id, redirect_uri=:redirect_uri, expires=:expires, scope=:scope, id_token =:id_token where authorization_code=:code', $this->config['code_table']));
        } else {
            $stmt = oci_parse($this->db, sprintf('INSERT INTO %s (authorization_code, client_id, user_id, redirect_uri, expires, scope, id_token) VALUES (:code, :client_id, :user_id, :redirect_uri, :expires, :scope, :id_token)', $this->config['code_table']));
        }
        oci_bind_by_name($stmt,':code',$code);
        oci_bind_by_name($stmt,':client_id',$client_id);
        oci_bind_by_name($stmt,':user_id',$user_id);
        oci_bind_by_name($stmt,':redirect_uri',$redirect_uri);
        oci_bind_by_name($stmt,':expires',$expires);
        oci_bind_by_name($stmt,':scope',$scope);
        oci_bind_by_name($stmt,':id_token',$id_token);
        if(!oci_execute($stmt)){
        	print_r(oci_error($stmt));
        	return false;
        }
        return true;
    }

    public function expireAuthorizationCode($code){
        $stmt = oci_parse($this->db, sprintf('DELETE FROM %s WHERE authorization_code = :code', $this->config['code_table']));
        oci_bind_by_name($stmt,':code',$code);
        if(!oci_execute($stmt)){
        	print_r(oci_error($stmt));
        	return false;
        }
        return true;
    }

    /* OAuth2\Storage\UserCredentialsInterface */
    public function checkUserCredentials($username, $password){
        if ($user = $this->getUser($username)) {
            return $this->checkPassword($user, $password);
        }
        return false;
    }

    public function getUserDetails($username){
        return $this->getUser($username);
    }

    /* UserClaimsInterface */
    public function getUserClaims($user_id, $claims){
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

    protected function getUserClaim($claim, $userDetails){
        $userClaims = array();
        $claimValuesString = constant(sprintf('self::%s_CLAIM_VALUES', strtoupper($claim)));
        $claimValues = explode(' ', $claimValuesString);

        foreach ($claimValues as $value) {
            $userClaims[$value] = isset($userDetails[$value]) ? $userDetails[$value] : null;
        }

        return $userClaims;
    }


    /* OAuth2\Storage\RefreshTokenInterface */
    public function getRefreshToken($refresh_token){
        $stmt = oci_parse($this->db, sprintf('SELECT * FROM %s WHERE refresh_token = :refresh_token', $this->config['refresh_token_table']));
        oci_bind_by_name($stmt,':refresh_token',$refresh_token);
        oci_execute($stmt);
        if ($token =  array_change_key_case(oci_fetch_assoc($stmt),CASE_LOWER)) {
            // convert expires to epoch time
            $token['expires'] = strtotime($token['expires']);
        }
        return $token;
    }



    public function setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope = null){
        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);
        $stmt = oci_parse($this->db, sprintf('INSERT INTO %s (refresh_token, client_id, user_id, expires, scope) VALUES (:refresh_token, :client_id, :user_id, :expires, :scope)', $this->config['refresh_token_table']));
        oci_bind_by_name($stmt,':refresh_token',$refresh_token);
        oci_bind_by_name($stmt,':client_id',$client_id);
        oci_bind_by_name($stmt,':user_id',$user_id);
        oci_bind_by_name($stmt,':expires',$expires);
        oci_bind_by_name($stmt,':scope',$scope);
        if(!@oci_execute($stmt)){
        	print_r(oci_error($stmt));
        	return false;
        }
        return true;
    }

    public function unsetRefreshToken($refresh_token){
        $stmt = oci_parse($this->db, sprintf('DELETE FROM %s WHERE refresh_token = :refresh_token', $this->config['refresh_token_table']));
        oci_bind_by_name($stmt,':refresh_token',$refresh_token);
        if(!oci_execute($stmt)){
        	print_r(oci_error($stmt));
        	return false;
        }
        return true;

    }



    /**
     * This function was modified to work with the same SGL patterns
     *   Student authentication using library password( from pergamum)
     *   And teachers from Oracle database
     *
     * @param array $user
     * @param string $password
     */
    protected function checkPassword($user, $password) {
    	$sql = sprintf('SELECT password
    			FROM	%s
    			WHERE password = \'%s\'
    			AND username =  '.$user['username'].'',
    			$this->config['user_table'],
    			$this->getEncryptedPassword($user['username'],$password));
	   	$stmt = oci_parse($this->db,$sql);
    	oci_execute($stmt);
    	if(!oci_fetch_assoc($stmt)){
			return false;
    	}

    	return true;
 	        //return $user['password'] == sha1($password);
    }

    public function getUser($username) {
    	$sql = sprintf('SELECT * from %s where username=:username', $this->config['user_table']);
        $stmt = oci_parse($this->db, $sql);
        $username = (int) $username;
        oci_bind_by_name($stmt,':username',$username);
        oci_execute($stmt);
        $userInfo = @array_change_key_case(oci_fetch_assoc($stmt),CASE_LOWER);
        if (!$userInfo) {
            return false;
        }

        // the default behavior is to use "username" as the user_id
        return array_merge(array(
            'user_id' => $username
        ), $userInfo);
    }


    /* ScopeInterface */
    public function scopeExists($scope){
        $scopes = explode(' ', $scope);
        $whereIn = implode(',', array_fill(0, count($scope), '?'));
		foreach($scopes as $scope){
			$params[] = ':'.$scope;
		}

        $stmt = oci_parse($this->db, sprintf('SELECT count(scope) as count FROM %s WHERE scope IN (%s)', $this->config['scope_table'], implode(', ',$params)));
        foreach($params as $param){
        	oci_bind_by_name($stmt,$param,str_replace(':','',$param));
        }
		oci_execute($stmt);
        if ($result = array_change_key_case(oci_fetch_assoc($stmt),CASE_LOWER)) {
            return $result['count'] == count($scopes);
        }

        return false;
    }

    public function getDefaultScope($client_id = null) {
        $stmt = oci_parse($this->db, sprintf('SELECT scope FROM %s WHERE is_default=\'Y\'', $this->config['scope_table']));
        oci_execute($stmt);
        if ($result = @array_change_key_case(oci_fetch_assoc($stmt),CASE_LOWER)) {

            $defaultScope = array_map(function ($row) {
                return $row['scope'];
            }, $result);

            return implode(' ', $defaultScope);
        }

        return null;
    }

    /* JWTBearerInterface */
    public function getClientKey($client_id, $subject){
        $stmt = oci_parse($this->db, $sql = sprintf('SELECT public_key from %s where client_id=:client_id AND subject=:subject', $this->config['jwt_table']));
        oci_bind_by_name($stmt,':client_id',$client_id);
        oci_bind_by_name($stmt,':subject',$subject);
        oci_execute($stmt);

        return oci_result($stmt,'PUBLIC_KEY');
    }

    public function getClientScope($client_id){
        if (!$clientDetails = $this->getClientDetails($client_id)) {
            return false;
        }

        if (isset($clientDetails['scope'])) {
            return $clientDetails['scope'];
        }
        return null;
    }

    public function getJti($client_id, $subject, $audience, $expires, $jti){
        $stmt = oci_parse($this->db, $sql = sprintf('SELECT * FROM %s WHERE issuer=:client_id AND subject=:subject AND audience=:audience AND expires=:expires AND jti=:jti', $this->config['jti_table']));

        $stmt->execute(compact('client_id', 'subject', 'audience', 'expires', 'jti'));

        oci_bind_by_name($stmt,':client_id',$client_id);
        oci_bind_by_name($stmt,':subject',$subject);
        oci_bind_by_name($stmt,':audience',$audience);
        oci_bind_by_name($stmt,':expires',$expires);
        oci_bind_by_name($stmt,':jti',$jti);
        oci_execute($stmt);

        if ($result =  array_change_key_case(oci_fetch_assoc($stmt),CASE_LOWER)) {
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

    public function setJti($client_id, $subject, $audience, $expires, $jti){
        $stmt = oci_parse($this->db, sprintf('INSERT INTO %s (issuer, subject, audience, expires, jti) VALUES (:client_id, :subject, :audience, :expires, :jti)', $this->config['jti_table']));
        oci_bind_by_name($stmt,':client_id',$client_id);
        oci_bind_by_name($stmt,':subject',$subject);
        oci_bind_by_name($stmt,':audience',$audience);
        oci_bind_by_name($stmt,':expires',$expires);
        oci_bind_by_name($stmt,':jti',$jti);
        if(!oci_execute($stmt)){
        	print_r(oci_error($stmt));
        	return false;
        }
        return true;
    }

    /* PublicKeyInterface */
    public function getPublicKey($client_id = null){
        $stmt = oci_parse($this->db, $sql = sprintf('SELECT public_key FROM %s WHERE client_id=:client_id OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC', $this->config['public_key_table']));
        oci_bind_by_name($stmt,':client_id',$client_id);
        oci_execute($stmt);
        if ($result =  array_change_key_case(oci_fetch_assoc($stmt),CASE_LOWER)) {
            return $result['public_key'];
        }
    }

    public function getPrivateKey($client_id = null){
        $stmt = oci_parse($this->db, $sql = sprintf('SELECT private_key FROM %s WHERE client_id=:client_id OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC', $this->config['public_key_table']));
        oci_bind_by_name($stmt,':client_id',$client_id);
        oci_execute($stmt);
        if ($result =  array_change_key_case(oci_fetch_assoc($stmt),CASE_LOWER)) {
            return $result['private_key'];
        }
    }

    public function getEncryptionAlgorithm($client_id = null){
        $stmt = oci_parse($this->db, $sql = sprintf('SELECT encryption_algorithm FROM %s WHERE client_id=:client_id OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC', $this->config['public_key_table']));
      	oci_bind_by_name($stmt,':client_id',$client_id);
        oci_execute($stmt);
        if ($result =  array_change_key_case(oci_fetch_assoc($stmt),CASE_LOWER)){
            return $result['encryption_algorithm'];
        }

        return 'RS256';
    }


    /**
     * DDL to create OAuth2 database and tables for PDO storage
     *
     * @see https://github.com/dsquier/oauth2-server-php-mysql
     */
    public function getBuildSql($dbName = 'oauth2_server_php'){
    	$sql = "
    	CREATE TABLE {$this->config['client_table']} (
    	client_id             VARCHAR(80)   NOT NULL,
    	client_secret         VARCHAR(80)   NOT NULL,
    	redirect_uri          VARCHAR(2000),
    	grant_types           VARCHAR(80),
    	scope                 VARCHAR(4000),
    	user_id               VARCHAR(80),
    	PRIMARY KEY (client_id)
    	);

    	CREATE TABLE {$this->config['access_token_table']} (
    	access_token         VARCHAR2(40)    NOT NULL,
    	client_id            VARCHAR2(80)    NOT NULL,
    	user_id              VARCHAR2(80),
    	expires              VARCHAR2(40)       NOT NULL,
    	scope                VARCHAR2(4000),
    	PRIMARY KEY (access_token)
    	);

    	CREATE TABLE {$this->config['code_table']} (
    	authorization_code  VARCHAR2(40)    NOT NULL,
    	client_id           VARCHAR2(80)    NOT NULL,
    	user_id             VARCHAR2(80),
    	redirect_uri        VARCHAR2(2000),
    	expires             VARCHAR2(80)      NOT NULL,
    	scope               VARCHAR2(4000),
    	id_token            VARCHAR2(1000),
    	PRIMARY KEY (authorization_code)
    	);

    	CREATE TABLE {$this->config['refresh_token_table']} (
    	refresh_token       VARCHAR2(40)    NOT NULL,
    	client_id           VARCHAR2(80)    NOT NULL,
    	user_id             VARCHAR2(80),
    	expires             VARCHAR2(80)      NOT NULL,
    	scope               VARCHAR2(4000),
    	PRIMARY KEY (refresh_token)
    	);

    	CREATE TABLE {$this->config['user_table']} (
    	username            VARCHAR(80),
    	password            VARCHAR(80),
    	first_name          VARCHAR(80),
    	last_name           VARCHAR(80),
    	email               VARCHAR(80),
    	email_verified      CHAR(1),
    	scope               VARCHAR(4000)
    	);

    	CREATE TABLE {$this->config['scope_table']} (
    	scope               VARCHAR(80)  NOT NULL,
    	is_default          CHAR(1),
    	PRIMARY KEY (scope)
    	);

    	CREATE TABLE {$this->config['jwt_table']} (
    	client_id           VARCHAR(80)   NOT NULL,
    	subject             VARCHAR(80),
    	public_key          VARCHAR(2000) NOT NULL
    	);

    	CREATE TABLE {$this->config['jti_table']} (
    	issuer              VARCHAR(80)   NOT NULL,
    	subject             VARCHAR(80),
    	audiance            VARCHAR(80),
    	expires             VARCHAR(80)   NOT NULL,
    	jti                 VARCHAR(2000) NOT NULL
    	);

    	CREATE TABLE {$this->config['public_key_table']} (
    	client_id            VARCHAR(80),
    	public_key           VARCHAR(2000),
    	private_key          VARCHAR(2000),
    	encryption_algorithm VARCHAR(100) DEFAULT 'RS256'
    	)
    	";

    	return $sql;
    }
}
