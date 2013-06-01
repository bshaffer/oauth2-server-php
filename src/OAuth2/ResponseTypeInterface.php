<?php

namespace OAuth2;

interface ResponseTypeInterface
{
    public function getAuthorizeResponse($params, $user_id = null);
}
