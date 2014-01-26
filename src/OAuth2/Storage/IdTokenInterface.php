<?php

namespace OAuth2\Storage;

/**
 * Implement this interface to specify where the OAuth2 Server
 * should get/save id tokens
 */
interface IdTokenInterface
{
    /**
     * Look up the id_token matching the supplied authorization code.
     *
     * @param $code
     * The authorization code.
     *
     * @return
     * An associative array as below, or NULL if no matching id_token was found:
     * - id_token: (optional) Stored id_token.
     * - client_id: Stored client identifier.
     * - user_id: (optional) Stored user identifier.
     * - expires: Stored expiration in unix timestamp.
     */
    public function getIdToken($code);

    /**
     * Store the supplied id token values to storage.
     *
     * We need to store access token data as we create and verify tokens.
     *
     * @param $id_token
     * The id_token to be stored.
     * @param $client_id
     * Client identifier to be stored.
     * @param $user_id
     * User identifier to be stored.
     * @param $expires
     * Expiration to be stored as a Unix timestamp.
     * @param $code
     * OPTIONAL The authorization code.
     */
    public function setIdToken($id_token, $client_id, $user_id, $expires, $code = null);
}
