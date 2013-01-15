<?php

/**
*
*/
class OAuth2_ResponseType_AuthorizationCode implements OAuth2_ResponseTypeInterface
{
    private $storage;
    private $config;

    public function __construct(OAuth2_Storage_AuthorizationCodeInterface $storage, array $config = array())
    {
        $this->storage = $storage;
        $this->config = array_merge(array(
            'enforce_redirect' => false,
            'auth_code_lifetime' => 30,
        ), $config);
    }

    // same params as above
    public function getAuthorizeResponse($params, $user_id = null)
    {
        // build the URL to redirect to
        $result = array('query' => array());

        $params += array('scope' => null, 'state' => null);

        $result["query"]["code"] = $this->createAuthorizationCode($params['client_id'], $user_id, $params['redirect_uri'], $params['scope']);

        if (isset($params['state'])) {
            $result["query"]["state"] = $params['state'];
        }

        return array($params['redirect_uri'], $result);
    }

    /**
     * Handle the creation of auth code.
     *
     * This belongs in a separate factory, but to keep it simple, I'm just
     * keeping it here.
     *
     * @param $client_id
     * Client identifier related to the access token.
     * @param $redirect_uri
     * An absolute URI to which the authorization server will redirect the
     * user-agent to when the end-user authorization step is completed.
     * @param $scope
     * (optional) Scopes to be stored in space-separated string.
     *
     * @ingroup oauth2_section_4
     */
    public function createAuthorizationCode($client_id, $user_id, $redirect_uri, $scope = null)
    {
        $code = $this->generateAuthorizationCode();
        $this->storage->setAuthorizationCode($code, $client_id, $user_id, $redirect_uri, time() + $this->config['auth_code_lifetime'], $scope);

        return $code;
    }

    public function enforceRedirect()
    {
        return $this->config['enforce_redirect'];
    }

    /**
     * Generates an unique auth code.
     *
     * Implementing classes may want to override this function to implement
     * other auth code generation schemes.
     *
     * @return
     * An unique auth code.
     *
     * @ingroup oauth2_section_4
     */
    protected function generateAuthorizationCode()
    {
        $tokenLen = 40;
        if (file_exists('/dev/urandom')) { // Get 100 bytes of random data
            $randomData = file_get_contents('/dev/urandom', false, null, 0, 100) . uniqid(mt_rand(), true);
        } else {
            $randomData = mt_rand() . mt_rand() . mt_rand() . mt_rand() . microtime(true) . uniqid(mt_rand(), true);
        }

        return substr(hash('sha512', $randomData), 0, $tokenLen);
    }
}
