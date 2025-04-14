<?php

namespace OAuth2\OpenID\Controller;

use OAuth2\Controller\AuthorizeController as BaseAuthorizeController;
use OAuth2\OpenID\Storage\UserClaimsInterface;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;
use OAuth2\Storage\ClientInterface;
use OAuth2\ScopeInterface;

/**
 * @see OAuth2\Controller\AuthorizeControllerInterface
 */
class AuthorizeController extends BaseAuthorizeController implements AuthorizeControllerInterface
{
    /**
     * @var mixed
     */
    private $nonce;

    /**
     * @var mixed
     */
    protected $code_challenge;

    /**
     * @var mixed
     */
    protected $code_challenge_method;

    /**
     * @var mixed
     */
    protected $userClaimsStorage;

    public function __construct(ClientInterface $clientStorage, UserClaimsInterface $userClaimsStorage, array $responseTypes = array(), array $config = array(), ScopeInterface $scopeUtil = null)
    {
        parent::__construct($clientStorage, $responseTypes, $config, $scopeUtil);
        $this->userClaimsStorage = $userClaimsStorage;
    }

    /**
     * Set not authorized response
     *
     * @param RequestInterface  $request
     * @param ResponseInterface $response
     * @param string            $redirect_uri
     * @param null              $user_id
     */
    protected function setNotAuthorizedResponse(RequestInterface $request, ResponseInterface $response, $redirect_uri, $user_id = null)
    {
        $prompt = $request->query('prompt', 'consent');
        if ($prompt == 'none') {
            if (is_null($user_id)) {
                $error = 'login_required';
                $error_message = 'The user must log in';
            } else {
                $error = 'interaction_required';
                $error_message = 'The user must grant access to your application';
            }
        } else {
            $error = 'consent_required';
            $error_message = 'The user denied access to your application';
        }

        $response->setRedirect($this->config['redirect_status_code'], $redirect_uri, $this->getState(), $error, $error_message);
    }

    /**
     * @TODO: add dependency injection for the parameters in this method
     *
     * @param RequestInterface $request
     * @param ResponseInterface $response
     * @param mixed $user_id
     * @return array
     */
    protected function buildAuthorizeParameters($request, $response, $user_id)
    {
        if (!$params = parent::buildAuthorizeParameters($request, $response, $user_id)) {
            return;
        }

        // Generate an id token if needed.
        if ($this->needsIdToken($this->getScope()) && $this->getResponseType() == self::RESPONSE_TYPE_AUTHORIZATION_CODE) {
            $userClaims = $this->userClaimsStorage->getUserClaims($user_id, $params['scope']);
            $params['id_token'] = $this->responseTypes['id_token']->createIdToken($this->getClientId(), $user_id, $this->nonce, $userClaims );
        }

        // add the nonce to return with the redirect URI
        $params['nonce'] = $this->nonce;

        // Add PKCE code challenge.
        $params['code_challenge'] = $this->code_challenge;
        $params['code_challenge_method'] = $this->code_challenge_method;

        return $params;
    }

    /**
     * @param RequestInterface $request
     * @param ResponseInterface $response
     * @return bool
     */
    public function validateAuthorizeRequest(RequestInterface $request, ResponseInterface $response)
    {
        if (!parent::validateAuthorizeRequest($request, $response)) {
            return false;
        }

        $nonce = $request->query('nonce');

        // Validate required nonce for "id_token" and "id_token token"
        if (!$nonce && in_array($this->getResponseType(), array(self::RESPONSE_TYPE_ID_TOKEN, self::RESPONSE_TYPE_ID_TOKEN_TOKEN))) {
            $response->setError(400, 'invalid_nonce', 'This application requires you specify a nonce parameter');

            return false;
        }

        $this->nonce = $nonce;

        $code_challenge = $request->query('code_challenge');
        $code_challenge_method = $request->query('code_challenge_method');

        if ($this->config['enforce_pkce']) {
            if (!$code_challenge) {
                $response->setError(400, 'missing_code_challenge', 'This application requires you provide a PKCE code challenge');

                return false;
            }

            if (preg_match('/^[A-Za-z0-9-._~]{43,128}$/', $code_challenge) !== 1) {
            $response->setError(400, 'invalid_code_challenge', 'The PKCE code challenge supplied is invalid');

            return false;
          }

            if (!in_array($code_challenge_method, array('plain', 'S256'), true)) {
                $response->setError(400, 'missing_code_challenge_method', 'This application requires you specify a PKCE code challenge method');

                return false;
            }
        }

        $this->code_challenge = $code_challenge;
        $this->code_challenge_method = $code_challenge_method;

        return true;
    }

    /**
     * Array of valid response types
     *
     * @return array
     */
    protected function getValidResponseTypes()
    {
        return array(
            self::RESPONSE_TYPE_ACCESS_TOKEN,
            self::RESPONSE_TYPE_AUTHORIZATION_CODE,
            self::RESPONSE_TYPE_ID_TOKEN,
            self::RESPONSE_TYPE_ID_TOKEN_TOKEN,
            self::RESPONSE_TYPE_CODE_ID_TOKEN,
        );
    }

    /**
     * Returns whether the current request needs to generate an id token.
     *
     * ID Tokens are a part of the OpenID Connect specification, so this
     * method checks whether OpenID Connect is enabled in the server settings
     * and whether the openid scope was requested.
     *
     * @param string $request_scope - A space-separated string of scopes.
     * @return boolean - TRUE if an id token is needed, FALSE otherwise.
     */
    public function needsIdToken($request_scope)
    {
        // see if the "openid" scope exists in the requested scope
        return $this->scopeUtil->checkScope('openid', $request_scope);
    }

    /**
     * @return mixed
     */
    public function getNonce()
    {
        return $this->nonce;
    }
}
