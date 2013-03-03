<?php

/**
 * Implement this interface to specify where the OAuth2 Server
 * should retrieve client information
 *
 * @author Brent Shaffer <bshafs@gmail.com>
 */
interface OAuth2_Storage_ClientInterface
{
    /**
     * Get client details corresponding client_id.
     *
     * OAuth says we should store request URIs for each registered client.
     * Implement this function to grab the stored URI for a given client id.
     *
     * @param $client_id
     * Client identifier to be check with.
     *
     * @return array
     * Client details. Only mandatory item is the "registered redirect URI", and MUST
     * return FALSE if the given client does not exist or is invalid.
     *
     * @ingroup oauth2_section_4
     */
    public function getClientDetails($client_id);
}
