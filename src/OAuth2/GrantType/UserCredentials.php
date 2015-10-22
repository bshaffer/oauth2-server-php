<?php

namespace OAuth2\GrantType;

use OAuth2\Storage\UserCredentialsInterface;
use OAuth2\ResponseType\AccessTokenInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
class UserCredentials implements GrantTypeInterface
{
    private $userInfo;

    protected $storage;

    /**
     * @param OAuth2\Storage\UserCredentialsInterface $storage REQUIRED Storage class for retrieving user credentials information
     */
    public function __construct(UserCredentialsInterface $storage)
    {
        $this->storage = $storage;
    }

    public function getQuerystringIdentifier()
    {
        return 'password';
    }

    public function validateRequest(RequestInterface $request, &$errors = null)
    {
        $body = json_decode((string) $request->getBody(), true);
        if (empty($body['password']) || empty($body['password'])) {
            $errors = array(
                'code' => 'invalid_request',
                'description' => 'Missing parameters: "username" and "password" required',
            );

            return null;
        }

        if (!$this->storage->checkUserCredentials($body['username'], $body['password'])) {
            $errors = array(
                'code' => 'invalid_grant',
                'description' => 'Invalid username and password combination',
            );

            return null;
        }

        $userInfo = $this->storage->getUserDetails($body['username']);

        if (empty($userInfo)) {
            $errors = array(
                'code' => 'invalid_grant',
                'description' => 'Unable to retrieve user information',
            );

            return null;
        }

        if (!isset($userInfo['user_id'])) {
            throw new \LogicException("you must set the user_id on the array returned by getUserDetails");
        }

        $this->userInfo = $userInfo;

        return true;
    }

    public function getClientId()
    {
        return null;
    }

    public function getUserId()
    {
        return $this->userInfo['user_id'];
    }

    public function getScope()
    {
        return isset($this->userInfo['scope']) ? $this->userInfo['scope'] : null;
    }

    public function createAccessToken(AccessTokenInterface $accessToken, $client_id, $user_id, $scope)
    {
        return $accessToken->createAccessToken($client_id, $user_id, $scope);
    }
}
