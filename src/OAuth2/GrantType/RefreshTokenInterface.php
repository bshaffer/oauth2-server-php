<?php

interface OAuth2_GrantType_RefreshTokenInterface extends OAuth2_GrantTypeInterface
{
    /**
     * @return
     * TRUE if the grant type requires a redirect_uri, FALSE if not
     */
    public function createRefreshToken($refresh_token, $client_id, $user_id, $scope = null);

    /**
     * Handle the creation of auth code.
     *
     * This belongs in a separate factory, but to keep it simple, I'm just
     * keeping it here.
     *
     * @param $client_id
     * Client identifier related to the access token.
     * @param $redirect_uri
     * An absolute URI to which the authorization server will redirect the
     * user-agent to when the end-user authorization step is completed.
     * @param $scope
     * (optional) Scopes to be stored in space-separated string.
     *
     * @ingroup oauth2_section_4
     */
    public function getRefreshTokenLifetime();
}

