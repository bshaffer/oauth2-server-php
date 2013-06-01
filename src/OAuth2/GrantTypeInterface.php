<?php

namespace OAuth2;

use OAuth2\ResponseType\AccessTokenInterface;

/**
 * Interface for all OAuth2 Grant Types
 */
interface GrantTypeInterface
{
    public function validateRequest(RequestInterface $request, ResponseInterface $response);
    public function getClientId();
    public function getUserId();
    public function getScope();
    public function createAccessToken(AccessTokenInterface $accessToken, $client_id, $user_id, $scope);
}
