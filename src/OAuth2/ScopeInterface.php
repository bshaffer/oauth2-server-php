<?php

/**
* Class to handle scope implementation logic
*/
interface OAuth2_ScopeInterface extends OAuth2_Storage_ScopeInterface
{
    /**
     * Check if everything in required scope is contained in available scope.
     *
     * @param $required_scope
     * A space-separated string of scopes.
     *
     * @return
     * TRUE if everything in required scope is contained in available scope,
     * and FALSE if it isn't.
     *
     * @see http://tools.ietf.org/html/rfc6749#section-7
     *
     * @ingroup oauth2_section_7
     */
    public function checkScope($required_scope, $available_scope);

    /**
     * Return scope info from request
     *
     * @param OAuth2_RequestInterface
     * Request object to check
     *
     * @return
     * string representation of requested scope
     */
    public function getScopeFromRequest(OAuth2_RequestInterface $request);
}
