<?php

namespace OAuth2\Encryption;

interface EncryptionInterface
{
    public function encode($payload, $key);
    public function decode($payload, $key);
}