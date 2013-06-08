<?php

/**
 * OAuth2_CompatibilityInterface
 * This interface exists because PHP 5.2 cannot combine matching
 * functions from separate interfaces.
 *
 * Even though OAuth2_ClientAssertionTypeInterface and OAuth2_GrantTypeInterface
 * have common methods, it doesn't actually make sense to extend a base interface.
 * However, this is temporarily required for the library to run in PHP 5.2
 *
 */
interface OAuth2_CompatibilityInterface
{
    public function validateRequest(OAuth2_RequestInterface $request, OAuth2_ResponseInterface $response);
    public function getClientId();
}