<?php

namespace OAuth2\Saml;

use OneLogin_Saml2_Response;

/**
 * This is an adapter that uses OneLogin utils
 * Class SamlAssertionDecoder.
 */
class Saml2Assertion implements Saml2AssertionInterface
{
    /**
     * @var OneLogin_Saml2_Response
     */
    protected $response;
    protected $settings;
    protected $assertion;
    protected $response_error;

    public function __construct($settings)
    {
        $this->settings = new \OneLogin_Saml2_Settings($settings);
    }

    public function setRawAssertion($samlAssertion)
    {
        $this->assertion = $samlAssertion;

        try {
            $this->response = new \OneLogin_Saml2_Response($this->settings, $samlAssertion);
        } catch (\Exception $e) {
            $this->response = null;
            $this->response_error = $e->getMessage();
        }
    }

    public function validate()
    {
        if (!isset($this->assertion)) {
            //this is a development error, die.
            throw new \Exception("SAML Assertion not set");
        }

        if (!isset($this->response)) {
            return array('error' => $this->response_error);
        }

        /*
         * Checks:
         * http://tools.ietf.org/html/draft-ietf-oauth-saml2-bearer-16#section-3
         *   1 - issuser = $idpData['entityId']  --> We only support 1 issuer (saml idp)
         *   2 - audience = $spData['entityId']  --> Get this one from
         *   3 - Subject = a - getNameId()
         *                 b - check getNameId() aginst client ID!
         *   4 - Expire = use getSessionNotOnOrAfter() !== null
         *   5, 6 - SubjectConfirmation = ok
         *   7, 8 - did idp authenticate the subject? = - not sure how to check
         *   9 - Attribute statements MAY be present = ok, get them with getAttributes()
         *   10 - Signature = Uses $idpData['x509cert'] and $idpData['certFingerprint'];
         *   11 - Encryption = ok (supported)
         *   12 - Other validations = ok, I guess it does!
         */

        if (!$this->response->isValid()) {
            return array('error' => $this->response->getError());
        }

        //3b - in case of client auth flow.
        //4 - make sure $this->saml_response->getSessionNotOnOrAfter() !== null ??
        return null;
    }

    /**
     * Gets the User identifier from the saml assertion. Note this may represent different attibutes based on idp config
     *         <NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
     *           brian@example.com
     *        </NameID>.
     *
     * @return string
     */
    public function getNameId()
    {
        $nameId = $this->response->getNameId();

        return $nameId;
    }
}
