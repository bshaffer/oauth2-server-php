<?php

namespace OAuth2\GrantType;

use OAuth2\Storage\DeviceCodeInterface;
use OAuth2\Storage\ClientInterface;
use OAuth2\ResponseType\DeviceCode as DeviceCodeResponseType;
use OAuth2\ResponseType\AccessTokenInterface;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;
use OAuth2\ClientAssertionType\ClientAssertionTypeInterface;

/**
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
class DeviceCode implements GrantTypeInterface
{
    /**
     * @var OAuth2\Storage\ClientInterface
     */
    protected $storage;

    /**
     * @param OAuth2\Storage\ClientInterface $storage REQUIRED Storage class for retrieving client information
     */
    public function __construct(ClientInterface $storage)
    {
        $this->storage = $storage;
    }

    public function getQuerystringIdentifier()
    {
        return 'device_code';
    }

    public function validateRequest(RequestInterface $request, ResponseInterface $response)
    {
        if (!$request->request('client_id')) {
            $response->setError(400, 'invalid_request', 'Missing parameter: "client_id" is required');

            return false;
        }

        /*
         * Ensure that the client_id existed
         */
        $client_id = $request->request('client_id');
        if (!$client = $this->storage->getClientDetails($client_id)) {
            $response->setError(400, 'invalid_client', 'The client id supplied is invalid');

            return false;
        }

        $this->client = $client;

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

    public function createAccessToken(AccessTokenInterface $deviceCode, $client_id, $user_id = null, $scope)
    {
        # public function createDeviceCode($client_id)
        $code = $deviceCode->createDeviceCode($client_id, $scope);
        return $code;
        /**
         * @TODO: add expiration check here???
         */
        #$this->storage->expireAuthorizationCode($this->authCode['code']);

        #return $token;
    }
}
