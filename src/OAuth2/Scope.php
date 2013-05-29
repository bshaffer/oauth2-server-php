<?php

/**
* @see OAuth2_ScopeInterface
*/
class OAuth2_Scope implements OAuth2_ScopeInterface
{
    private $storage;

    /**
     * @param mixed @storage
     * Either an array of supported scopes, or an instance of OAuth2_Storage_ScopeInterface
     */
    public function __construct($storage = null)
    {
        if (is_null($storage) || is_array($storage)) {
            $storage = new OAuth2_Storage_Memory((array) $storage);
        }

        if (!$storage instanceof OAuth2_Storage_ScopeInterface) {
            throw new InvalidArgumentException("Argument 1 to OAuth2_Scope must be null, an array, or instance of OAuth2_Storage_ScopeInterface");
        }

        $this->storage = $storage;
    }

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
    public function checkScope($required_scope, $available_scope)
    {
        $required_scope = explode(' ', trim($required_scope));
        $available_scope = explode(' ', trim($available_scope));
        return (count(array_diff($required_scope, $available_scope)) == 0);
    }

    /**
     * Check if the provided scope exists in storage.
     *
     * @param $scope
     *   A space-separated string of scopes.
     * @param $client_id
     *   The requesting client.
     *
     * @return
     *   TRUE if it exists, FALSE otherwise.
     */
    public function scopeExists($scope, $client_id = null)
    {
        return $this->storage->scopeExists($scope, $client_id);
    }

    public function getScopeFromRequest(OAuth2_RequestInterface $request)
    {
        // "scope" is valid if passed in either POST or QUERY
        return $request->request('scope', $request->query('scope'));
    }

    public function getDefaultScope()
    {
        return $this->storage->getDefaultScope();
    }
}
