<?php

interface OAuth2_ResponseType_AccessTokenInterface extends OAuth2_ResponseTypeInterface
{
    public function createAccessToken($client_id, $user_id, $scope = null, $includeRefreshToken = true);
}