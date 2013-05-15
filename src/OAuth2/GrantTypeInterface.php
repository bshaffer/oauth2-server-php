<?php

/**
 * Interface for all OAuth2 Grant Types
 *
 * @see OAuth2_CompatibilityInterface
 */
interface OAuth2_GrantTypeInterface extends OAuth2_CompatibilityInterface
{
    public function getUserId();
    public function getScope();
    public function createAccessToken(OAuth2_ResponseType_AccessTokenInterface $accessToken, $client_id, $user_id, $scope);
}
