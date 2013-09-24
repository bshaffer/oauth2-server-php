<?php

namespace OAuth2\Storage;

use OAuth2\Storage\AccessTokenInterface;
use OAuth2\Encryption\EncryptionInterface;
use OAuth2\Encryption\Jwt;

/**
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
class PublicKey implements CryptoTokenInterface
{
    protected $publicKey;
    protected $privateKey;
    protected $config;
    protected $secondaryStorage;
    protected $encryptionUtil;

    /**
     * @param string $publicKey
     * the public key encryption to use
     *
     * @param string $privateKey (optional)
     * (optional) the private key to use to sign tokens
     * this is only required for token granting, and can be omitted for resource servers,
     * as only the publc key is required for crypto token verification
     *
     * @param array $config
     * (optional) configuration array. Valid parameters are
     * - algorithm
     *  the algorithm to use for encryption. This is passed to the
     *  EncryptionInterface object.
     *  @see OAuth2\Encryption\Jwt::verifySignature
     *
     * @param OAuth2\Storage\AccessTokenInterface $secondaryStorage
     * (optional) persist the access token to another storage. This is useful if
     * you want to retain access token grant information somewhere, but
     * is not necessary when using this grant type.
     *
     * @param OAuth2\Encryption\EncryptionInterface $encryptionUtil
     * (optional) class to use for "encode" and "decode" functions.
     */
    public function __construct($publicKey, $privateKey = null, array $config = array(), AccessTokenInterface $secondaryStorage = null, EncryptionInterface $encryptionUtil = null)
    {
        $this->config = array_merge(array(
            'algorithm' => 'RS256',
        ), $config);
        $this->publicKey  = $publicKey;
        $this->privateKey = $privateKey;
        $this->secondaryStorage = $secondaryStorage;
        if (is_null($encryptionUtil)) {
            $encryptionUtil = new Jwt();
        }
        $this->encryptionUtil = $encryptionUtil;
    }

    public function encodeToken(array $token)
    {
        if (is_null($this->privateKey)) {
            throw new LogicException('A private key must be passed into the constructor to encode a token');
        }
        return $this->encryptionUtil->encode($token, $this->privateKey, $this->config['algorithm']);
    }

    public function getAccessToken($oauth_token)
    {
        if (!$decodedToken = $this->encryptionUtil->decode($oauth_token, $this->publicKey, $this->config['algorithm'])) {
            return false;
        }

        return $decodedToken;
    }

    public function setAccessToken($oauth_token, $client_id, $user_id, $expires, $scope = null)
    {
        if ($this->secondaryStorage) {
            return $this->secondaryStorage->setAccessToken($oauth_token, $client_id, $user_id, $expires, $scope);
        }
    }
}
