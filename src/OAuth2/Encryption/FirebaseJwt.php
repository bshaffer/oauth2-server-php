<?php

namespace OAuth2\Encryption;

/**
 * Bridge file to use the firebase/php-jwt package for JWT encoding and decoding.
 * @author Francis Chuang <francis.chuang@gmail.com>
 */
class FirebaseJwt implements EncryptionInterface
{
    public function __construct()
    {
        if (!class_exists('\Firebase\JWT\JWT')) {
            throw new \ErrorException('firebase/php-jwt must be installed to use this feature. You can do this by running "composer require firebase/php-jwt"');
        }
    }

    public function encode($payload, $key, $alg = 'HS256', $keyId = null)
    {
        return \Firebase\JWT\JWT::encode($payload, $key, $alg, $keyId);
    }

    public function decode($jwt, $key = null, $allowedAlgorithms = null)
    {
        try {

            //Maintain BC: Do not verify if no algorithms are passed in.
            if (!$allowedAlgorithms) {
                $key = null;
            }

            return (array)\Firebase\JWT\JWT::decode($jwt, $key, $allowedAlgorithms);
        } catch (\Exception $e) {
            return false;
        }
    }

    public function urlSafeB64Encode($data)
    {
        return \Firebase\JWT\JWT::urlsafeB64Encode($data);
    }

    public function urlSafeB64Decode($b64)
    {
        return \Firebase\JWT\JWT::urlsafeB64Decode($b64);
    }
}
