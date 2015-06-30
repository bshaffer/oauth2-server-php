<?php

namespace OAuth2\GrantType;

use OAuth2\Storage\DeviceCodeInterface;
use OAuth2\ResponseType\AccessTokenInterface;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;

/**
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
class DeviceToken implements GrantTypeInterface
{
    /**
     * @var OAuth2\Storage\ClientInterface
     */
    protected $storage;

    /**
     * @param OAuth2\Storage\ClientInterface $storage REQUIRED Storage class for retrieving client information
     */
    public function __construct(DeviceCodeInterface $storage)
    {
        $this->storage = $storage;
    }

    public function getQuerystringIdentifier()
    {
        return 'device_token';
    }

    public function validateRequest(RequestInterface $request, ResponseInterface $response)
    {
        if (!$request->request('client_id')) {
            $response->setError(400, 'invalid_request', 'Missing parameter: "client_id" is required');

            return false;
        }

        if (!$request->request('code')) {
            $response->setError(400, 'invalid_request', 'Missing parameter: "code" is required');

            return false;
        }

        /*
         * Ensure that the device code exists
         */
        $client_id = $request->request('client_id');
        $code = $request->request('code');
        if (!$deviceCode = $this->storage->getDeviceCode($code, $client_id)) {
            $response->setError(400, 'bad_verification_code', 'Bad verification code');

            return false;
        }

        /*
         * Verify expiration
         */
        if ($deviceCode["expires"] < time()) {
            $response->setError(400, 'code_expired', "The authorization code has expired");

            return false;
        }

        /*
         * Ensure that the user confirmed this code
         */
        if (!$deviceCode['user_id']) {
            $response->setError(400, 'authorization_pending', '');
            return false;
        }

        $this->deviceCode = $deviceCode;

        return true;
    }

    public function getClientId()
    {
        return $this->client['client_id'];
    }

    public function getScope()
    {
        return isset($this->client['scope']) ? $this->client['scope'] : null;
    }

    public function getUserId()
    {
        return isset($this->client['user_id']) ? $this->client['user_id'] : null;
    }

    public function createAccessToken(AccessTokenInterface $accessToken, $client_id, $user_id, $scope)
    {
        $includeRefreshToken = true;

        return $accessToken->createAccessToken($client_id, $user_id, $scope, $includeRefreshToken);
        //$this->storage->expireAuthorizationCode($this->authCode['code']);
        // Delete device code?
    }
}
