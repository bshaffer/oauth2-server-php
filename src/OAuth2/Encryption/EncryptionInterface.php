<?php

namespace OAuth2\Encryption;

interface EncryptionInterface
{
    public function getSupportedAlgorithms($type = null);
    public function encode($payload, $key, $algorithm = null);
    public function decode($payload, $key, $allowed_algorithms = null);
    public function urlSafeB64Encode($data);
    public function urlSafeB64Decode($b64);
}
