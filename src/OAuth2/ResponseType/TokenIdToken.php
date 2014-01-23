<?php

namespace OAuth2\ResponseType;

use OAuth2\Encryption\EncryptionInterface;
use OAuth2\Encryption\Jwt;
use OAuth2\Storage\IdTokenInterface as IdTokenStorageInterface;
use OAuth2\Storage\RefreshTokenInterface;
use OAuth2\Storage\PublicKeyInterface;

class TokenIdToken extends IdToken implements IdTokenInterface, AccessTokenInterface
{
    protected $publicKeyStorage;
    protected $encryptionUtil;

    public function __construct(IdTokenStorageInterface $tokenStorage, PublicKeyInterface $publicKeyStorage = null, RefreshTokenInterface $refreshStorage = null, array $config = array(), EncryptionInterface $encryptionUtil = null)
    {
        // @TODO: find a good way to remove super globals
        if (!isset($config['issuer'])) {
            throw new \LogicException('config parameter "issuer" must be set');
        }

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
        $at_hash = substr($accessToken, 0, strlen($accessToken) / 2);

        $idToken = $this->createIdToken($this->config['issuer'], $user_id, $client_id, $expires, $iat, $iat, $at_hash);

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
}
