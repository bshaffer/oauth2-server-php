<?php

namespace OAuth2\Controller;

use OAuth2\TokenType\TokenTypeInterface;
use OAuth2\Storage\AccessTokenInterface;
use OAuth2\ScopeInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use OAuth2\Scope;

/**
 * @see OAuth2\Controller\ResourceControllerInterface
 */
class ResourceController implements ResourceControllerInterface
{
    private $token;

    protected $tokenType;
    protected $tokenStorage;
    protected $config;
    protected $scopeUtil;

    public function __construct(TokenTypeInterface $tokenType, AccessTokenInterface $tokenStorage, $config = array(), ScopeInterface $scopeUtil = null)
    {
        $this->tokenType = $tokenType;
        $this->tokenStorage = $tokenStorage;

        $this->config = array_merge(array(
            'www_realm' => 'Service',
        ), $config);

        if (is_null($scopeUtil)) {
            $scopeUtil = new Scope();
        }
        $this->scopeUtil = $scopeUtil;
    }

    public function verifyResourceRequest(RequestInterface $request, ResponseInterface $response, StreamInterface $stream, $scope = null)
    {
        try {
            $token = $this->getAccessTokenData($request, $response);

            // Check if we have token data
            if (is_null($token)) {
                return false;
            }

            /**
             * Check scope, if provided
             * If token doesn't have a scope, it's null/empty, or it's insufficient, then throw 403
             * @see http://tools.ietf.org/html/rfc6750#section-3.1
             */
            if ($scope && (!isset($token["scope"]) || !$token["scope"] || !$this->scopeUtil->checkScope($scope, $token["scope"]))) {
                throw new ResponseException(
                    'insufficient_scope',
                    'The request requires higher privileges than provided by the access token',
                    '#section-3.1',
                    403
                );
            }
        } catch (ResponseException $e) {
            $authHeader = sprintf('%s realm="%s"', $this->tokenType->getTokenType(), $this->config['www_realm']);

            if ($shortCode = $e->getShortCode()) {
                $authHeader = sprintf('%s, error="%s"', $authHeader, $shortCode);
                if ($description = $e->getDescription()) {
                    $authHeader = sprintf('%s, error_description="%s"', $authHeader, $description);
                }
            }

            $stream->write($e->getMessage());

            return $response
                ->withStatus($e->getStatusCode() ?: 401)
                ->withHeader('WWW-Authenticate', $authHeader)
                ->withHeader('Content-Type', 'application/json')
                ->withBody($stream);
        }

        // allow retrieval of the token
        $this->token = $token;

        return $response;
    }

    public function getAccessTokenData(RequestInterface $request, ResponseInterface $response)
    {
        // Get the token parameter
        if ($token_param = $this->tokenType->getAccessTokenParameter($request, $response)) {
            // Get the stored token data (from the implementing subclass)
            // Check we have a well formed token
            // Check token expiration (expires is a mandatory paramter)
            if (!$token = $this->tokenStorage->getAccessToken($token_param)) {
                throw new ResponseException('invalid_token', 'The access token provided is invalid');
            } elseif (!isset($token["expires"]) || !isset($token["client_id"])) {
                throw new ResponseException('malformed_token', 'Malformed token (missing "expires")');
            } elseif (time() > $token["expires"]) {
                throw new ResponseException('expired_token', 'The access token provided has expired');
            } else {
                return $token;
            }
        }

        // if no authentication was provided, do not return error information
        // @see http://tools.ietf.org/html/rfc6750#section-3.1
        throw new ResponseException();
    }

    // convenience method to allow retrieval of the token
    public function getToken()
    {
        return $this->token;
    }
}

class ResponseException extends \LogicException {

  public function __construct($short_code, $description){
    $this->shortCode = $short_code;
    $this->description = $description;
    $this->statusCode = 401;
    parent::__construct(json_encode(['code'=>$short_code, 'error_description' => $description]),   $this->statusCode);

  }

  public function getDescription(){
    return $this->description;
  }

  public function getShortCode(){
    return $this->shortCode;
  }

  public function getStatusCode(){
    return $this->statusCode;
  }

}
