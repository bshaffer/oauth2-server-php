<?php

namespace OAuth2;

/**
 * Interface for all OAuth2 Client Assertion Types
 */
interface ClientAssertionTypeInterface
{
    public function validateRequest(RequestInterface $request, ResponseInterface $response);
    public function getClientId();
}
