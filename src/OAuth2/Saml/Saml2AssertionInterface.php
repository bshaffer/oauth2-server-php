<?php

namespace OAuth2\Saml;

interface Saml2AssertionInterface
{
    /**
     * Sets the assertion to operate with.
     *
     * @param $samlAssertion string The saml assertion parameter
     */
    public function setRawAssertion($samlAssertion);

    /**
     * Validate current samlAssertion. Returns error array when assertion is not valid
     */
    public function validate();

    /**
     * @return string a string that identifies the user
     */
    public function getNameId();
}
