<?php

interface OAuth2_ResponseTypeInterface
{
    public function getAuthorizeResponse($params, $user_id = null);
}
