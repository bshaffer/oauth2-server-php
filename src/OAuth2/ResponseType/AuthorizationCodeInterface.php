<?php

namespace OAuth2\ResponseType;

/**
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
interface AuthorizationCodeInterface extends ResponseTypeInterface
{
    /**
     * @return
     * TRUE if the grant type requires a redirect_uri, FALSE if not
     */
    public function enforceRedirect();

    /**
     * Handle the creation of the authorization code.
     *
     * @param $client_id    client identifier related to the authorization code
     * @param $user_id      user id associated with the authorization code
     * @param $redirect_uri an absolute URI to which the authorization server will redirect the
     *                      user-agent to when the end-user authorization step is completed.
     * @param $scope        OPTIONAL scopes to be stored in space-separated string.
     *
     * @see http://tools.ietf.org/html/rfc6749#section-4
     * @ingroup oauth2_section_4
     */
    public function createAuthorizationCode($client_id, $user_id, $redirect_uri, $scope = null);
}
