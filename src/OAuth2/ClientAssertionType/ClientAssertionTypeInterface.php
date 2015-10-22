<?php

namespace OAuth2\ClientAssertionType;

use Psr\Http\Message\RequestInterface;

/**
 * Interface for all OAuth2 Client Assertion Types
 */
interface ClientAssertionTypeInterface
{
    public function validateRequest(RequestInterface $request, &$errors = null);
    public function getClientId();
}
