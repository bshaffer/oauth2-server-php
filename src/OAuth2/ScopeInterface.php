<?php

namespace OAuth2;

use OAuth2\Storage\ScopeInterface as ScopeStorageInterface;

/**
 * Class to handle scope implementation logic
 *
 * @see \OAuth2\Storage\ScopeInterface
 */
interface ScopeInterface extends ScopeStorageInterface
{
    /**
     * Check if everything in required scope is contained in available scope.
     *
     * @param string $required_scope  - A space-separated string of scopes.
     * @param string $available_scope - A space-separated string of scopes.
     * @return bool                - TRUE if everything in required scope is contained in available scope and FALSE
     *                                  if it isn't.
     *
     * @see http://tools.ietf.org/html/rfc6749#section-7
     *
     * @ingroup oauth2_section_7
     */
    public function checkScope(string $required_scope, string $available_scope): bool;

    /**
     * Return scope info from request
     *
     * @param RequestInterface $request - Request object to check
     * @return string                   - representation of requested scope
     */
    public function getScopeFromRequest(RequestInterface $request): string;
}
