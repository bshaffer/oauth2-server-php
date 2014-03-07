<?php

namespace OAuth2\ResponseType;

interface IdTokenInterface extends ResponseTypeInterface
{
    /**
     * Create the id token.
     *
     * If Authorization Code Flow is used, the id_token is generated when the
     * authorization code is issued, and later returned from the token endpoint
     * together with the access_token.
     * If the Implicit Flow is used, the token and id_token are generated and
     * returned together.
     *
     * @param string $client_id The client id.
     * @param string $user_id The user id.
     * @param string $nonce OPTIONAL The nonce.
     * @param string $access_token OPTIONAL The access token, if known.
     *
     * @return string The ID Token represented as a JSON Web Token (JWT).
     *
     * @see http://openid.net/specs/openid-connect-core-1_0.html#IDToken
     */
    public function createIdToken($client_id, $user_id, $nonce = null, $access_token = null);
}
