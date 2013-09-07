<?php

namespace OAuth2\ResponseType;

use OAuth2\Storage\AccessTokenInterface as AccessTokenStorageInterface;
use OAuth2\Storage\RefreshTokenInterface;

/**
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
class AccessToken implements AccessTokenInterface
{
    protected $tokenStorage;
    protected $refreshStorage;

    public function __construct(AccessTokenStorageInterface $tokenStorage, RefreshTokenInterface $refreshStorage = null, array $config = array())
    {
        $this->tokenStorage = $tokenStorage;
        $this->refreshStorage = $refreshStorage;

        $this->config = array_merge(array(
            'token_type'             => 'bearer',
            'access_lifetime'        => 3600,
            'refresh_token_lifetime' => 1209600,
        ), $config);
    }

    public function getAuthorizeResponse($params, $user_id = null)
    {
        // build the URL to redirect to
        $result = array('query' => array());

        $params += array('scope' => null, 'state' => null);

        /*
         * a refresh token MUST NOT be included in the fragment
         *
         * @see http://tools.ietf.org/html/rfc6749#section-4.2.2
         */
        $includeRefreshToken = false;
        $result["fragment"] = $this->createAccessToken($params['client_id'], $user_id, $params['scope'], $includeRefreshToken);

        if (isset($params['state'])) {
            $result["fragment"]["state"] = $params['state'];
        }

        return array($params['redirect_uri'], $result);
    }

    /**
     * Handle the creation of access token, also issue refresh token if supported / desirable.
     *
     * @param $client_id
     * Client identifier related to the access token.
     * @param $user_id
     * User ID associated with the access token
     * @param $scope
     * (optional) Scopes to be stored in space-separated string.
     * @param bool $includeRefreshToken
     * If true, a new refresh_token will be added to the response
     *
     * @see http://tools.ietf.org/html/rfc6749#section-5
     * @ingroup oauth2_section_5
     */
    public function createAccessToken($client_id, $user_id, $scope = null, $includeRefreshToken = true)
    {
        $token = array(
            "access_token" => $this->generateAccessToken(),
            "expires_in" => $this->config['access_lifetime'],
            "token_type" => $this->config['token_type'],
            "scope" => $scope
        );

        $this->tokenStorage->setAccessToken($token["access_token"], $client_id, $user_id, $this->config['access_lifetime'] ? time() + $this->config['access_lifetime'] : null, $scope);

        /*
         * Issue a refresh token also, if we support them
         *
         * Refresh Tokens are considered supported if an instance of OAuth2_Storage_RefreshTokenInterface
         * is supplied in the constructor
         */
        if ($includeRefreshToken && $this->refreshStorage) {
            $token["refresh_token"] = $this->generateRefreshToken();
            $this->refreshStorage->setRefreshToken($token['refresh_token'], $client_id, $user_id, time() + $this->config['refresh_token_lifetime'], $scope);
        }

        return $token;
    }

    /**
     * Generates an unique access token.
     *
     * Implementing classes may want to override this function to implement
     * other access token generation schemes.
     *
     * @return
     * An unique access token.
     *
     * @ingroup oauth2_section_4
     */
    protected function generateAccessToken()
    {
        $tokenLen = 40;
        if (@file_exists('/dev/urandom')) { // Get 100 bytes of random data
            $randomData = file_get_contents('/dev/urandom', false, null, 0, 100) . uniqid(mt_rand(), true);
        } else {
            $randomData = mt_rand() . mt_rand() . mt_rand() . mt_rand() . microtime(true) . uniqid(mt_rand(), true);
        }
        return substr(hash('sha512', $randomData), 0, $tokenLen);
    }

    /**
     * Generates an unique refresh token
     *
     * Implementing classes may want to override this function to implement
     * other refresh token generation schemes.
     *
     * @return
     * An unique refresh.
     *
     * @ingroup oauth2_section_4
     * @see OAuth2::generateAccessToken()
     */
    protected function generateRefreshToken()
    {
        return $this->generateAccessToken(); // let's reuse the same scheme for token generation
    }
}
