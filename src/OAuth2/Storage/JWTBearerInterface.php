<?php

/**
 * Implement this interface to specify where the OAuth2 Server
 * should get the JWT key for clients
 *
 * @TODO consider extending ClientInterface, as this will almost always
 * be the same storage as retrieving clientData
 *
 * @author F21
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
interface OAuth2_Storage_JWTBearerInterface
{
    /**
     * Get the public key associated with a client_id
     *
     * @param $client_id
     * Client identifier to be check with.
     *
     * @return
     * STRING Return the public key for the client_id if it exists, and MUST return FALSE if it doesn't.
     * @endcode
     */
    public function getClientKey($client_id, $subject);
}
