<?php

namespace OAuth2\ResponseType;

use OAuth2\Encryption\EncryptionInterface;
use OAuth2\Encryption\Jwt;
use OAuth2\Storage\IdTokenInterface as IdTokenStorageInterface;
use OAuth2\Storage\RefreshTokenInterface;
use OAuth2\Storage\PublicKeyInterface;

class IdToken extends AccessToken implements IdTokenInterface
{
    protected $publicKeyStorage;
    protected $encryptionUtil;

    public function __construct(IdTokenStorageInterface $tokenStorage, PublicKeyInterface $publicKeyStorage = null, RefreshTokenInterface $refreshStorage = null, array $config = array(), EncryptionInterface $encryptionUtil = null)
    {
        $this->publicKeyStorage = $publicKeyStorage;
        if (is_null($encryptionUtil)) {
            $encryptionUtil = new Jwt();
        }
        $this->encryptionUtil = $encryptionUtil;
        parent::__construct($tokenStorage, $refreshStorage, $config);
    }

    /**
     * Handle the creation of id token, also issue refresh token if supported / desirable.
     *
     * @param $client_id
     * Client identifier related to the access token.
     * @param $user_id
     * User ID associated with the access token
     * @param $scope
     * (optional) Scopes to be stored in space-separated string.
     * @param bool $includeRefreshToken
     * If true, a new refresh_token will be added to the response
     *
     * @see http://tools.ietf.org/html/rfc6749#section-5
     * @ingroup oauth2_section_5
     */
    public function createAccessToken($client_id, $user_id, $scope = null, $includeRefreshToken = true)
    {
        // token to encrypt
        $iat = time();
        $expires = $iat + $this->config['access_lifetime'];
        $accessToken = $this->generateAccessToken();
        $prefix = (isset($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) == 'on') ? 'https://' : 'http://';

        $idToken = array(
            'iss'        => $prefix . $_SERVER['SERVER_NAME'],
            'sub'        => $user_id,
            'aud'        => $client_id,
            'exp'        => $expires,
            'iat'        => $iat,
            'auth_time'  => $iat,
            'at_hash'    => substr($accessToken, 0, strlen($accessToken) / 2),
        );

        /*
         * Encode the token data into a single id_token string.
         */
        $idToken = $this->encodeToken($idToken, $client_id);
        $this->tokenStorage->setAccessToken($accessToken, $client_id, $user_id, $this->config['access_lifetime'] ? $expires : null, $scope, $idToken);

        // Token to return to the client.
        $token = array(
            'access_token' => $this->generateAccessToken(),
            'id_token' => $idToken,
            'expires_in' => $this->config['access_lifetime'],
            'token_type' => $this->config['token_type'],
            'scope' => $scope
        );

        /*
         * Issue a refresh token also, if we support them
         *
         * Refresh Tokens are considered supported if an instance of OAuth2_Storage_RefreshTokenInterface
         * is supplied in the constructor
         */
        if ($includeRefreshToken && $this->refreshStorage) {
            $token["refresh_token"] = $this->generateRefreshToken();
            $this->refreshStorage->setRefreshToken($idToken['refresh_token'], $client_id, $user_id, time() + $this->config['refresh_token_lifetime'], $scope);
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
