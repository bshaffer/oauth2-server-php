<?php

namespace OAuth2\ResponseType;

interface ResponseTypeInterface
{
    public function getAuthorizeResponse($params, $user_id = null);
}
