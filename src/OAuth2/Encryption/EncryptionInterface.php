<?php

namespace OAuth2\Encryption;

interface EncryptionInterface
{
    public function encode($payload, $key, $algorithm = null, $keyId = null);

    public function decode($payload, $key, array $allowedAlgorithms = array());
    public function urlSafeB64Encode($data);
    public function urlSafeB64Decode($b64);
}
