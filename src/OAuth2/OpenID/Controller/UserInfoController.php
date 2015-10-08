<?php

namespace OAuth2\OpenID\Controller;

use OAuth2\Scope;
use OAuth2\TokenType\TokenTypeInterface;
use OAuth2\Storage\AccessTokenInterface;
use OAuth2\OpenID\Storage\UserClaimsInterface;
use OAuth2\Controller\ResourceController;
use OAuth2\ScopeInterface;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;

/**
 * @see OAuth2\Controller\UserInfoControllerInterface
 */
class UserInfoController extends ResourceController implements UserInfoControllerInterface
{
    /**
     * TODO: Check if $token is necessary here. It is already declared inside the ResourceController that is extended.
     *
     * @var array
     */
    private $token;

    /**
     * @var UserClaimsInterface
     */
    protected $userClaimsStorage;

    /**
     * Constructor
     *
     * @param TokenTypeInterface   $tokenType
     * @param AccessTokenInterface $tokenStorage
     * @param UserClaimsInterface  $userClaimsStorage
     * @param array                $config
     * @param ScopeInterface       $scopeUtil
     */
    public function __construct(TokenTypeInterface $tokenType, AccessTokenInterface $tokenStorage, UserClaimsInterface $userClaimsStorage, $config = array(), ScopeInterface $scopeUtil = null)
    {
        $this->tokenType = $tokenType;
        $this->tokenStorage = $tokenStorage;
        $this->userClaimsStorage = $userClaimsStorage;

        $this->config = array_merge(array(
            'www_realm' => 'Service',
        ), $config);

        if (is_null($scopeUtil)) {
            $scopeUtil = new Scope();
        }
        $this->scopeUtil = $scopeUtil;
    }

    /**
     * Handle the user info request
     *
     * @param RequestInterface $request
     * @param ResponseInterface $response
     * @return void
     */
    public function handleUserInfoRequest(RequestInterface $request, ResponseInterface $response)
    {
        if (!$this->verifyResourceRequest($request, $response, 'openid')) {
            return;
        }

        $token = $this->getToken();
        $claims = $this->userClaimsStorage->getUserClaims($token['user_id'], $token['scope']);
        // The sub Claim MUST always be returned in the UserInfo Response.
        // http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
        $claims += array(
            'sub' => $token['user_id'],
        );
        $response->addParameters($claims);
    }
}