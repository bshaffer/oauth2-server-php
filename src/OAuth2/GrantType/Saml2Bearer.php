<?php

namespace OAuth2\GrantType;

use OAuth2\ResponseType\AccessTokenInterface;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;
use OAuth2\Saml\Saml2AssertionInterface;

/**
 * The Saml2 bearer authorization grant implements SAML2 assertions as a grant type per the IETF draft.
 *
 * NOTE: the authorization grant is not a clientAssertion.
 *
 * @see http://tools.ietf.org/html/draft-ietf-oauth-saml2-bearer-16#section-4
 *
 * @author aacotroneo
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
class Saml2Bearer implements GrantTypeInterface
{
    protected $samlAssertion;

    /**
     * @param array                   $settings      configuration for the default SAML2Assertion
     * @param Saml2AssertionInterface $samlAssertion
     */
    public function __construct($settings = array(), Saml2AssertionInterface $samlAssertion = null)
    {
        //@todo settings should not depend on the implementation - now they are just what onelogin library wants

        if (is_null($samlAssertion)) {
            $samlAssertion = new \OAuth2\Saml\Saml2Assertion($settings);
        }

        $this->samlAssertion = $samlAssertion;
    }

    /**
     * Returns the grant_type get parameter to identify the grant type request as SAML2 bearer authorization grant.
     *
     * @see OAuth2\GrantType\GrantTypeInterface::getQuerystringIdentifier()
     *
     * @return string The string identifier for grant_type.
     */
    public function getQuerystringIdentifier()
    {
        return 'urn:ietf:params:oauth:grant-type:saml2-bearer';
    }

    /**
     * Validates the data from the SAML2 assertion.
     *
     * @see OAuth2\GrantType\GrantTypeInterface::getTokenData()
     *
     * @param \OAuth2\RequestInterface  $request
     * @param \OAuth2\ResponseInterface $response
     *
     * @return mixed TRUE if the Saml2 request is valid and can be decoded. Otherwise, FALSE is returned.
     */
    public function validateRequest(RequestInterface $request, ResponseInterface $response)
    {
        if ($request->request("assertion", false) === false) {
            $response->setError(400, 'invalid_request', 'Missing parameters: "assertion" required');

            return null;
        }

        $rawSaml2Assertion = $request->request('assertion');
        $this->samlAssertion->setRawAssertion($rawSaml2Assertion);
        $error = $this->samlAssertion->validate();

        if (!empty($error)) {
            $response->setError(400, 'invalid_grant', $error['error']);

            return null;
        }

        return true;
    }

    public function getClientId()
    {
        return null;
    }

    public function getUserId()
    {
        return $this->samlAssertion->getNameId();
    }

    public function getScope()
    {
        return null;
    }

    /**
     * The token does not include a Refresh token. Clients may present the same assertion to
     * get another token.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-assertions-18#section-4.1
     * @see OAuth2\GrantType\GrantTypeInterface::createAccessToken()
     */
    public function createAccessToken(AccessTokenInterface $accessToken, $client_id, $user_id, $scope)
    {
        $includeRefreshToken = false;

        return $accessToken->createAccessToken($client_id, $user_id, $scope, $includeRefreshToken);
    }
}
