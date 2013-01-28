<?php

/**
 * Implement this interface to specify where the OAuth2 Server
 * should retrieve data involving the relevent scopes associated
 * with this implementation.
 *
 * @author Brent Shaffer <bshafs@gmail.com>
 */
interface OAuth2_Storage_ScopeInterface
{
    /**
     * What scopes are supported by the oauth2 server
     * Scope names must follow the format specified in the
     * oauth2 spec
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-3.3
     *
     * @return
     * array or space-delimited string of supported scopes
     *
     * ex:
     *     array(
     *         'one-scope',
     *         'two-scope',
     *         'red-scope',
     *         'blue-scope',
     *     );
     * ex:
     *     'one-scope two-scope red-scope blue-scope'
     *
     */
    public function getSupportedScopes();

    /**
     * The default scope to use in the event the client
     * does not request one.  by returning "null", a
     * request_error is returned by the server to force a
     * scope request by the client
     *
     * @return
     * string representation of default scope, or null to
     * force scope request by the client
     *
     * ex:
     *     'default'
     * ex:
     *     null
     */
    public function getDefaultScope();
}
