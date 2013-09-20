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
    protected $secondaryStorage;
    protected $encryptionUtil;

    public function __construct($publicKey, $privateKey, AccessTokenInterface $secondaryStorage = null, EncryptionInterface $encryptionUtil = null)
    {
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
        return $this->encryptionUtil->encode(json_encode($token), $this->privateKey);
    }

    public function getAccessToken($oauth_token)
    {
        if (!$decodedToken = $this->encryptionUtil->decode($oauth_token, $this->publicKey)) {
            return false;
        }

        return json_decode($decodedToken, true);
    }

    public function setAccessToken($oauth_token, $client_id, $user_id, $expires, $scope = null)
    {
        if ($this->secondaryStorage) {
            return $this->secondaryStorage($oauth_token, $client_id, $user_id, $expires, $scope);
        }
    }
}
