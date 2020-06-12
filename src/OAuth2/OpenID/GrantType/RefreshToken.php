<?php


namespace OAuth2\OpenID\GrantType;


use OAuth2\Encryption\FirebaseJwt;
use OAuth2\GrantType\RefreshToken as BaseRefreshToken;
use OAuth2\OpenID\ResponseType\IdTokenInterface;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;
use OAuth2\ResponseType\AccessTokenInterface;
use OAuth2\Storage\RefreshTokenInterface;

/**
 * Class RefreshToken
 * @package OAuth2\OpenID\GrantType
 * @author Adis Azhar <adisazhar123 at gmail dot com>
 */
class RefreshToken extends BaseRefreshToken
{
    /**
     * @var IdTokenInterface $idToken
     */
    private $idToken;

    public function __construct(RefreshTokenInterface $storage, IdTokenInterface $idToken, $config = array())
    {
        $this->idToken = $idToken;
        parent::__construct($storage, $config);
    }

    /**
     * Holds the refresh token
     *
     * @var array $refreshToken
     */
    private $refreshToken;

    /**
     * Validate refresh token request. This overrides method from base class
     *
     * @param RequestInterface $request
     * @param ResponseInterface $response
     * @return bool|mixed|void|null
     * @throws \Exception
     */
    public function validateRequest(RequestInterface $request, ResponseInterface $response)
    {
        if (! in_array('openid', explode(' ', $request->request('scope')))) {
            throw new \Exception('Refresh token request for OAuth 2.0 must not use this grant type.');
        }

        if (! $request->request('refresh_token')) {
            $response->setError(400, 'invalid_request', 'Missing parameter: "refresh_token" is required');

            return null;
        }

        if (! $refreshToken = $this->storage->getRefreshToken($request->request('refresh_token'))) {
            $response->setError(400, 'invalid_grant', 'Invalid refresh token');

            return null;
        }

        $this->refreshToken = $refreshToken;

        return true;
    }

    public function createAccessToken(AccessTokenInterface $accessToken, $client_id, $user_id, $scope)
    {
        /*
         * It is optional to force a new refresh token when a refresh token is used.
         * However, if a new refresh token is issued, the old one MUST be expired
         * @see http://tools.ietf.org/html/rfc6749#section-6
         */
        $issueNewRefreshToken = $this->config['always_issue_new_refresh_token'];
        $unsetRefreshToken = $this->config['unset_refresh_token_after_use'];
        $token = $accessToken->createAccessToken($client_id, $user_id, $scope, $issueNewRefreshToken);

        if ($unsetRefreshToken) {
            $this->storage->unsetRefreshToken($this->refreshToken['refresh_token']);
        }

        // TODO: Set configuration
        $tempConfig = true;
        if ($this->config['issue_id_token_on_token_refresh'] || $tempConfig) {
//            $client_id, $userInfo, $nonce = null, $userClaims = null, $access_token = null
            $jwt = new FirebaseJwt();
            $decodedIdToken = $jwt->decode($this->refreshToken['id_token'], null, false);
            $claims = array(
                'iss' => $decodedIdToken['iss'],
                'sub' => $decodedIdToken['sub'],
                'aud' => $decodedIdToken['aud']
            );

            if (array_key_exists('auth_time', $decodedIdToken)) {
                $authTime = array('auth_time' => $decodedIdToken['auth_time']);
                $claims += $authTime;
            }

            if (array_key_exists('azp', $decodedIdToken)) {
                $azp = array('azp' => $decodedIdToken['azp']);
                $claims += $azp;
            }

            $idToken = array('id_token' => $this->idToken->createIdToken($client_id, $user_id, null, $claims, null));
            $token += $idToken;
        }

        return $token;
    }
}