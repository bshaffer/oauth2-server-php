<?php

namespace OAuth2\OpenID\Controller;

use OAuth2\ResponseType\AccessTokenInterface;
use OAuth2\ClientAssertionType\ClientAssertionTypeInterface;
use OAuth2\Controller\TokenControllerInterface;
use OAuth2\ScopeInterface;
use OAuth2\Storage\ClientInterface;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;
use OAuth2\Controller\TokenController as BaseController;
use OAuth2\OpenID\ResponseType\IdTokenInterface;
use OAuth2\OpenID\Storage\UserClaimsInterface;

class TokenController extends BaseController implements TokenControllerInterface
{
    protected $idToken;
    protected $userClaimsStorage;

    public function __construct(AccessTokenInterface $accessToken, ClientInterface $clientStorage, IdTokenInterface $idToken, UserClaimsInterface $userClaimsStorage, array $grantTypes = array(), ClientAssertionTypeInterface $clientAssertionType = null, ScopeInterface $scopeUtil = null)
    {
        parent::__construct($accessToken, $clientStorage, $grantTypes, $clientAssertionType, $scopeUtil);

        $this->idToken = $idToken;
        $this->userClaimsStorage = $userClaimsStorage;
    }

    public function grantAccessToken(RequestInterface $request, ResponseInterface $response)
    {
        $accessToken = parent::grantAccessToken($request, $response);

        if ($accessToken != null && array_key_exists('scope', $accessToken) && in_array('openid', explode(' ', $accessToken['scope']))) {
            $grantTypeIdentifier = $request->request('grant_type');
            $grantType = $this->grantTypes[$grantTypeIdentifier];

            $userId = $grantType->getUserId();
            $scope = $grantType->getScope();

            $claims = $this->userClaimsStorage->getUserClaims($userId, $scope);
            $accessToken['id_token'] = $this->idToken->createIdToken($grantType->getClientId(), $userId, null, $claims);
        }

        return $accessToken;
    }
}
