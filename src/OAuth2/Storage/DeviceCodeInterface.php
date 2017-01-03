<?php

namespace OAuth2\Storage;

/**
 * Implement this interface to specify where the OAuth2 Server
 * should get/save device code
 *
 * @author TroRg <trogg at gmail dot com>
 */
interface DeviceCodeInterface
{
    /**
     * Look up the supplied oauth_token from storage.
     *
     * We need to retrieve access token data as we create and verify tokens.
     * If $code is NULL
     *
     * @param $code
     * oauth_token to be check with.
     * @param $client_id
     * Client id
     *
     * @return
     * An associative array as below, and return NULL if the supplied oauth_token
     * is invalid:
     * - client_id: Stored client identifier.
     * - code: Stored device code
     * - user_code: 6 character user code.
     * - expires: Stored expiration in unix timestamp.
     * - scope: (optional) Stored scope values in space-separated string.
     */
    public function getDeviceCode($code, $client_id);

    /**
     * Store the supplied access token values to storage.
     *
     * We need to store access token data as we create and verify tokens.
     *
     * @param $device_code           oauth_token to be stored.
     * @param $user_code      user_code to be stored.
     * @param $client_id      client identifier to be stored.
     * @param $user_id        user identifier to be stored.
     * @param int    $expires expiration to be stored as a Unix timestamp.
     * @param string $scope   OPTIONAL Scopes to be stored in space-separated string.
     */
    public function setDeviceCode($device_code, $user_code, $client_id, $user_id, $expires, $scope = null);
}
