<?php

namespace OAuth2\OpenID\GrantType;

use OAuth2\GrantType\AuthorizationCode as BaseAuthorizationCode;
use OAuth2\ResponseType\AccessTokenInterface;

/**
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
class AuthorizationCode extends BaseAuthorizationCode
{
    public function createAccessToken(AccessTokenInterface $accessToken, $client_id, $user_id, $scope)
    {
        $includeRefreshToken = true;
        if (isset($this->authCode['id_token'])) {
            // OpenID Connect requests include the refresh token only if the
            // offline_access scope has been requested and granted.
            $scopes = explode(' ', trim($scope));
            $includeRefreshToken = in_array('offline_access', $scopes);
        }

        $token = $accessToken->createAccessToken($client_id, $user_id, $scope, $includeRefreshToken);
        if (isset($this->authCode['id_token'])) {
            $token['id_token'] = $this->authCode['id_token'];
        }

        $this->storage->expireAuthorizationCode($this->authCode['code']);

        return $token;
    }
}
