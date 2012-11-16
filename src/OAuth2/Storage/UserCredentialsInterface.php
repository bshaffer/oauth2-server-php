<?php

/**
 * Storage engines that support the "Resource Owner Password Credentials"
 * grant type should implement this interface
 *
 * @author Dave Rochwerger <catch.dave@gmail.com>
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.3
 */
interface OAuth2_Storage_UserCredentialsInterface
{

    /**
     * Grant access tokens for basic user credentials.
     *
     * Check the supplied username and password for validity.
     *
     * You can also use the $client_id param to do any checks required based
     * on a client, if you need that.
     *
     * Required for OAuth2::GRANT_TYPE_USER_CREDENTIALS.
     *
     * @param $username
     * Username to be check with.
     * @param $password
     * Password to be check with.
     *
     * @return
     * TRUE if the username and password are valid, and FALSE if it isn't.
     * Moreover, if the username and password are valid, and you want to
     * verify the scope of a user's access, return an associative array
     * with the scope values as below. We'll check the scope you provide
     * against the requested scope before providing an access token:
     * @code
     * return array(
     * 'scope' => <stored scope values (space-separated string)>,
     * );
     * @endcode
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.3
     *
     * @ingroup oauth2_section_4
     */
    public function checkUserCredentials($username, $password);

    /**
     * @return
     * ARRAY the associated "scope" or "user_id" values if applicable, or an empty array
     * if this does not apply
     *
     */
    public function getUserDetails($username);
}