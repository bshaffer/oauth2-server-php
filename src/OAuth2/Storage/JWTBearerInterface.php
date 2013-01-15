<?php

/**
 * All storage engines need to implement this interface in order to use OAuth2 server
 *
 * @author David Rochwerger <catch.dave@gmail.com>
 */
interface OAuth2_Storage_JWTBearerInterface extends OAuth2_Storage_ClientInterface
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
    public function getClientKey($client_id);
}
