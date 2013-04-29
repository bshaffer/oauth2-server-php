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

    /**
     * Check restricted grant types of corresponding client identifier.
     *
     * If you want to restrict clients to certain grant types, override this
     * function.
     *
     * @param $client_id
     * Client identifier to be check with.
     * @param $grant_type
     * Grant type to be check with
     *
     * @return
     * TRUE if the grant type is supported by this client identifier, and
     * FALSE if it isn't.
     *
     * @ingroup oauth2_section_4
     */
    public function checkRestrictedGrantType($client_id, $grant_type);
}
