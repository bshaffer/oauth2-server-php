<?php

namespace OAuth2\Storage;

/**
 * Implement this interface to specify where the OAuth2 Server
 * should get public/private key information
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
interface PublicKeyInterface
{
    /**
     * @param mixed $client_id
     * @return mixed
     */
    public function getPublicKey(string $client_id = null): mixed;

    /**
     * @param mixed $client_id
     * @return mixed
     */
    public function getPrivateKey(string $client_id = null): mixed;

    /**
     * @param mixed $client_id
     * @return mixed
     */
    public function getEncryptionAlgorithm(string $client_id = null): mixed;
}