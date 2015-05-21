<?php

namespace OAuth2\ResponseType;

use OAuth2\Encryption\EncryptionInterface;
use OAuth2\Encryption\Jwt;
use OAuth2\Storage\AccessTokenInterface as AccessTokenStorageInterface;
use OAuth2\Storage\RefreshTokenInterface;
use OAuth2\Storage\PublicKeyInterface;
use OAuth2\Storage\Memory;

/**
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
class JwtAccessToken extends AccessToken
{
    protected $publicKeyStorage;
    protected $encryptionUtil;

    /**
     * @param $config
     *  - store_encrypted_token_string (bool true)
     *       whether the entire encrypted string is stored,
     *       or just the token ID is stored
     */
    public function __construct(PublicKeyInterface $publicKeyStorage = null, AccessTokenStorageInterface $tokenStorage = null, RefreshTokenInterface $refreshStorage = null, array $config = array(), EncryptionInterface $encryptionUtil = null)
    {
        $this->publicKeyStorage = $publicKeyStorage;
        $config = array_merge(array(
            'store_encrypted_token_string' => true,
            'issuer' => ''
        ), $config);
        if (is_null($tokenStorage)) {
            // a pass-thru, so we can call the parent constructor
            $tokenStorage = new Memory();
        }
        if (is_null($encryptionUtil)) {
            $encryptionUtil = new Jwt();
        }
        $this->encryptionUtil = $encryptionUtil;
        parent::__construct($tokenStorage, $refreshStorage, $config);
    }

    /**
     * Handle the creation of access token, also issue refresh token if supported / desirable.
     *
     * @param $client_id
     * Client identifier related to the access token.
     * @param $user_id
     * User ID associated with the access token
     * @param $scope
     * (optional) Scopes to be stored in space-separated string.
     * @param bool $includeRefreshToken
     *                                  If true, a new refresh_token will be added to the response
     *
     * @see http://tools.ietf.org/html/rfc6749#section-5
     * @ingroup oauth2_section_5
     */
    public function createAccessToken($client_id, $user_id, $scope = null, $includeRefreshToken = true)
    {
        // token to encrypt
        $expires = time() + $this->config['access_lifetime'];
        $id = $this->generateAccessToken();
        $jwtAccessToken = array(
            'id'         => $id, // for BC (see #591)
            'jti'        => $id,
            'iss'        => $this->config['issuer'],
            'aud'        => $client_id,
            'sub'        => $user_id,
            'exp'        => $expires,
            'iat'        => time(),
            'token_type' => $this->config['token_type'],
            'scope'      => $scope
        );

        /*
         * Encode the token data into a single access_token string
         */
        $access_token = $this->encodeToken($jwtAccessToken, $client_id);

        /*
         * Save the token to a secondary storage.  This is implemented on the
         * OAuth2\Storage\JwtAccessToken side, and will not actually store anything,
         * if no secondary storage has been supplied
         */
        $token_to_store = $this->config['store_encrypted_token_string'] ? $access_token : $jwtAccessToken['id'];
        $this->tokenStorage->setAccessToken($token_to_store, $client_id, $user_id, $this->config['access_lifetime'] ? time() + $this->config['access_lifetime'] : null, $scope);

        // token to return to the client
        $token = array(
            'access_token' => $access_token,
            'expires_in' => $this->config['access_lifetime'],
            'token_type' => $this->config['token_type'],
            'scope' => $scope
        );

        /*
         * Issue a refresh token also, if we support them
         *
         * Refresh Tokens are considered supported if an instance of OAuth2\Storage\RefreshTokenInterface
         * is supplied in the constructor
         */
        if ($includeRefreshToken && $this->refreshStorage) {
            $refresh_token = $this->generateRefreshToken();
            $expires = 0;
            if ($this->config['refresh_token_lifetime'] > 0) {
                $expires = time() + $this->config['refresh_token_lifetime'];
            }
            $this->refreshStorage->setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope);
            $token['refresh_token'] = $refresh_token;
        }

        return $token;
    }

    protected function encodeToken(array $token, $client_id = null)
    {
        $private_key = $this->publicKeyStorage->getPrivateKey($client_id);
        $algorithm   = $this->publicKeyStorage->getEncryptionAlgorithm($client_id);

        return $this->encryptionUtil->encode($token, $private_key, $algorithm);
    }
}
