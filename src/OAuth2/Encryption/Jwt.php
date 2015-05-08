<?php

namespace OAuth2\Encryption;

/**
 * Bridge file to use the firebase/php-jwt package for JWT encoding and decoding.
 * @author Francis Chuang <francis.chuang@gmail.com>
 */
class Jwt implements EncryptionInterface
{
    public function __construct()
    {
        if (!class_exists('\JWT')) {
            throw new \ErrorException('firebase/php-jwt must be installed to use this feature. You can do this by running "composer require firebase/php-jwt"');
        }
    }

    public function encode($payload, $key, $alg = 'HS256', $keyId = null)
    {
        return \JWT::encode($payload, $key, $alg, $keyId);
    }

    public function decode($jwt, $key = null, array $allowedAlgorithms = array())
    {
        return (array)\JWT::decode($jwt, $key, $allowedAlgorithms);
    }

    public function urlSafeB64Encode($data)
    {
        return \JWT::urlsafeB64Encode($data);
    }

    public function urlSafeB64Decode($b64)
    {
        return \JWT::urlsafeB64Decode($b64);
    }
}
