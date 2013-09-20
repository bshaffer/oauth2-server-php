<?php

namespace OAuth2\Storage;

/**
 * Implement this interface to specify where the OAuth2 Server
 * should get/save access tokens
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
interface CryptoTokenInterface extends AccessTokenInterface
{
    function encodeToken(array $token);
}