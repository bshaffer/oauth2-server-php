<?php

namespace OAuth2\Storage;

/**
 * Implement this interface to specify where the OAuth2 Server
 * should retrieve data involving the relevent scopes associated
 * with this implementation.
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
interface ScopeInterface
{
    /**
     * Check if the provided scope exists.
     *
     * @param $scope
     * A space-separated string of scopes.
     * @param $client_id
     * The requesting client.
     *
     * @return
     * TRUE if it exists, FALSE otherwise.
     */
    public function scopeExists($scope, $client_id = null);

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
    public function getDefaultScope($client_id = null);
}
