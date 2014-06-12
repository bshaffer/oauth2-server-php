<?php

namespace OAuth2\OpenID\Controller;

use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;

interface AuthorizeControllerInterface
{
    const RESPONSE_TYPE_ID_TOKEN = 'id_token';
    const RESPONSE_TYPE_TOKEN_ID_TOKEN = 'token id_token';
}
