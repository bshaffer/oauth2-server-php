<?php

/**
 * Implement this interface to specify how the OAuth2 Server
 * should verify client credentials
 *
 * @author Brent Shaffer <bshafs@gmail.com>
 */
interface OAuth2_Storage_ClientCredentialsInterface extends OAuth2_Storage_ClientInterface
{

    /**
     * Make sure that the client credentials is valid.
     *
     * @param $client_id
     * Client identifier to be check with.
     * @param $client_secret
     * (optional) If a secret is required, check that they've given the right one.
     *
     * @return
     * TRUE if the client credentials are valid, and MUST return FALSE if it isn't.
     * @endcode
     *
     * @see http://tools.ietf.org/html/rfc6749#section-3.1
     *
     * @ingroup oauth2_section_3
     */
    public function checkClientCredentials($client_id, $client_secret = null);
}
