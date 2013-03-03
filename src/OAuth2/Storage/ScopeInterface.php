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
     * @see http://tools.ietf.org/html/rfc6749#section-3.3
     *
     * @param $client_id
     * The requesting client
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
    public function getSupportedScopes($client_id = null);

    /**
     * The default scope to use in the event the client
     * does not request one. By returning "false", a
     * request_error is returned by the server to force a
     * scope request by the client. By returning "null",
     * opt out of requiring scopes
     *
     * @return
     * string representation of default scope, null if
     * scopes are not defined, or false to force scope
     * request by the client
     *
     * ex:
     *     'default'
     * ex:
     *     null
     */
    public function getDefaultScope();
}
