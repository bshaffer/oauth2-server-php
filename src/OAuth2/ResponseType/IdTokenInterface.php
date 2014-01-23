<?php

namespace OAuth2\ResponseType;

interface IdTokenInterface extends ResponseTypeInterface
{
    public function createIdToken($iss, $sub, $aud, $exp, $iat, $auth_time, $at_hash = null);
}
