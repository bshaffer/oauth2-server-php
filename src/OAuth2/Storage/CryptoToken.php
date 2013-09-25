<?php

namespace OAuth2\Storage;

use OAuth2\Encryption\EncryptionInterface;
use OAuth2\Encryption\Jwt;

/**
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
class CryptoToken implements AccessTokenInterface
{
    protected $publicKeyStorage;
    protected $tokenStorage;
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
     * - encryption_algorithm
     *  the algorithm to use for encryption. This is passed to the
     *  EncryptionInterface object.
     *  @see OAuth2\Encryption\Jwt::verifySignature
     *
     * @param OAuth2\Storage\AccessTokenInterface $tokenStorage
     * (optional) persist the access token to another storage. This is useful if
     * you want to retain access token grant information somewhere, but
     * is not necessary when using this grant type.
     *
     * @param OAuth2\Encryption\EncryptionInterface $encryptionUtil
     * (optional) class to use for "encode" and "decode" functions.
     */
    public function __construct(PublicKeyInterface $publicKeyStorage, AccessTokenInterface $tokenStorage = null, EncryptionInterface $encryptionUtil = null)
    {
        $this->publicKeyStorage = $publicKeyStorage;
        $this->tokenStorage = $tokenStorage;
        if (is_null($encryptionUtil)) {
            $encryptionUtil = new Jwt;
        }
        $this->encryptionUtil = $encryptionUtil;
    }

    public function getAccessToken($oauth_token)
    {
        // just decode the token, don't verify
        if (!$tokenData = $this->encryptionUtil->decode($oauth_token, null, false)) {
            return false;
        }

        $client_id  = isset($tokenData['client_id']) ? $tokenData['client_id'] : null;
        $public_key = $this->publicKeyStorage->getPublicKey($client_id);
        $algorithm  = $this->publicKeyStorage->getEncryptionAlgorithm($client_id);

        // now that we have the client_id, verify the token
        if (false === $this->encryptionUtil->decode($oauth_token, $public_key, $algorithm)) {
            return false;
        }

        return $tokenData;
    }

    public function setAccessToken($oauth_token, $client_id, $user_id, $expires, $scope = null)
    {
        if ($this->tokenStorage) {
            return $this->tokenStorage->setAccessToken($oauth_token, $client_id, $user_id, $expires, $scope);
        }
    }
}
