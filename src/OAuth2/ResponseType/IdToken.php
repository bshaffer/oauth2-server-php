<?php

namespace OAuth2\ResponseType;

use OAuth2\Encryption\EncryptionInterface;
use OAuth2\Encryption\Jwt;
use OAuth2\Storage\IdTokenInterface as IdTokenStorageInterface;
use OAuth2\Storage\RefreshTokenInterface;
use OAuth2\Storage\PublicKeyInterface;

class IdToken implements IdTokenInterface
{
    protected $publicKeyStorage;
    protected $encryptionUtil;
    protected $tokenStorage;

    public function __construct(IdTokenStorageInterface $tokenStorage, PublicKeyInterface $publicKeyStorage = null, array $config = array(), EncryptionInterface $encryptionUtil = null)
    {
        // @TODO: find a good way to remove super globals
        if (!isset($config['issuer'])) {
            throw new \LogicException('config parameter "issuer" must be set');
        }

        $this->publicKeyStorage = $publicKeyStorage;
        if (is_null($encryptionUtil)) {
            $encryptionUtil = new Jwt();
        }
        $this->encryptionUtil = $encryptionUtil;
        $this->tokenStorage   = $tokenStorage;
    }

    public function getAuthorizeResponse($params, $user_id = null)
    {
        // build the URL to redirect to
        $result = array('query' => array());

        $params += array('scope' => null, 'state' => null);

        // create id token parameters
        $iss = $this->config['issuer'];
        $sub = $user_id;
        $aud = $params['client_id'];
        $iat = time();
        $exp = $iat + $this->config['id_lifetime'];
        $auth_time = $iat;

        // create access token hash
        $accessToken = $this->generateAccessToken();
        $at_hash = substr($accessToken, 0, strlen($accessToken) / 2);

        $id_token = $this->createIdToken($iss, $sub, $aud, $iat, $exp, $auth_time, $at_hash);

        $result["fragment"] = array('id_token' => $id_token);

        if (isset($params['state'])) {
            $result["fragment"]["state"] = $params['state'];
        }

        return array($params['redirect_uri'], $result);
    }

    public function createIdToken($iss, $sub, $aud, $iat, $exp, $auth_time, $at_hash = null)
    {
        $idToken = array(
            'iss'        => $iss,
            'sub'        => $sub,
            'aud'        => $aud,
            'exp'        => $exp,
            'iat'        => $iat,
            'auth_time'  => $auth_time,
        );

        if ($at_hash) {
            $token['at_hash'] = $at_hash;
        }

        /*
         * Encode the token data into a single id_token string.
         */
        $idToken = $this->encodeToken($token, $client_id);

        return $idToken;
    }

    protected function encodeToken(array $token, $client_id = null)
    {
        $private_key = $this->publicKeyStorage->getPrivateKey($client_id);
        $algorithm   = $this->publicKeyStorage->getEncryptionAlgorithm($client_id);

        return $this->encryptionUtil->encode($token, $private_key, $algorithm);
    }
}
