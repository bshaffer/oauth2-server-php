<?php

namespace OAuth2\OpenID\ResponseType;

class CodeIdToken implements CodeIdTokenInterface
{
    protected $authCode;
    protected $idToken;

    public function __construct(AuthorizationCodeInterface $authCode, IdTokenInterface $idToken)
    {
        $this->authCode = $authCode;
        $this->idToken = $idToken;
    }

    public function getAuthorizeResponse($params, $user_id = null)
    {
        $result = $this->authCode->getAuthorizeResponse($params, $user_id);
        $id_token = $this->idToken->getAuthorizeResponse($params, $user_id)[1]['fragment']['id_token'];
        $result[1]['query']['id_token'] = $id_token;

        return $result;
    }
}
