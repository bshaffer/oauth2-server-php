<?php

namespace OAuth2\GrantType;

use OAuth2\ClientAssertionType\HttpBasic;
use OAuth2\ResponseType\AccessTokenInterface;

/**
 * @author Brent Shaffer <bshafs at gmail dot com>
 *
 * @see OAuth2_ClientAssertionType_HttpBasic
 */
class ClientCredentials extends HttpBasic implements GrantTypeInterface
{
    public function getQuerystringIdentifier()
    {
        return 'client_credentials';
    }

    public function getScope()
    {
        return null;
    }

    public function getUserId()
    {
        return null;
    }

    public function createAccessToken(AccessTokenInterface $accessToken, $client_id, $user_id, $scope)
    {
        /*
         * Client Credentials Grant does NOT include a refresh token
         * @see http://tools.ietf.org/html/rfc6749#section-4.4.3
         */
        $includeRefreshToken = false;
        return $accessToken->createAccessToken($client_id, $user_id, $scope, $includeRefreshToken);
    }
}
