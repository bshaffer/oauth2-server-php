<?php

/**
*
*/
class OAuth2_ResponseType_AccessToken implements OAuth2_ResponseType_AccessTokenInterface
{
    private $tokenStorage;
    private $refreshStorage;

    public function __construct(OAuth2_Storage_AccessTokenInterface $tokenStorage, OAuth2_Storage_RefreshTokenInterface $refreshStorage = null, array $config = array())
    {
        $this->tokenStorage = $tokenStorage;
        $this->refreshStorage = $refreshStorage;

        $this->config = array_merge(array(
            'token_type'             => 'bearer',
            'access_lifetime'        => 3600,
            'refresh_token_lifetime' => 1209600,
            'implicit_pass_scope'    => true,
        ), $config);
    }

    // same params as above
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

        // Unset scope if spacified, for cases where passing it would breach
        // the maximum URL length.
        if (!$this->config['implicit_pass_scope']) {
            unset($result['fragment']['scope']);
        }
        if (isset($params['state'])) {
            $result["fragment"]["state"] = $params['state'];
        }

        return array($params['redirect_uri'], $result);
    }

    /**
     * Handle the creation of access token, also issue refresh token if support.
     *
     * This belongs in a separate factory, but to keep it simple, I'm just
     * keeping it here.
     *
     * @param $client_id
     * Client identifier related to the access token.
     * @param $scope
     * (optional) Scopes to be stored in space-separated string.
     * @param bool $excludeRefreshToken
     * If true, the refresh_token will be omitted from the response
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
        if (file_exists('/dev/urandom')) { // Get 100 bytes of random data
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
