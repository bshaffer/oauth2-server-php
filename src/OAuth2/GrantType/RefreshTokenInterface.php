<?php

interface OAuth2_GrantType_RefreshTokenInterface extends OAuth2_GrantTypeInterface
{
    /**
     * @return
     * TRUE if the grant type requires a redirect_uri, FALSE if not
     */
    public function saveRefreshToken($refresh_token, $client_id, $user_id, $scope = null);

    public function getRefreshTokenLifetime();
}

