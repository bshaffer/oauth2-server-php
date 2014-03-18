<?php

namespace OAuth2\Encryption;

interface EncryptionInterface
{
    public function encode($payload, $key, $algorithm = null);
    public function decode($payload, $key, $algorithm = null);
    public function urlSafeB64Encode($data);
    public function urlSafeB64Decode($b64);
}
