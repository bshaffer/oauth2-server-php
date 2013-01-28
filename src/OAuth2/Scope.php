<?php

/**
* @see OAuth2_ScopeInterface
*/
class OAuth2_Scope implements OAuth2_ScopeInterface
{
    private $storage;

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
     * Required scope to be check with.
     *
     * @return
     * TRUE if everything in required scope is contained in available scope,
     * and FALSE if it isn't.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-7
     *
     * @ingroup oauth2_section_7
     */
    public function checkScope($required_scope, $available_scope)
    {
        // The required scope should match or be a subset of the available scope
        if (!is_array($required_scope)) {
            $required_scope = explode(' ', trim($required_scope));
        }

        if (!is_array($available_scope)) {
            $available_scope = explode(' ', trim($available_scope));
        }

        return (count(array_diff($required_scope, $available_scope)) == 0);
    }

    public function getScopeFromRequest(OAuth2_RequestInterface $request)
    {
        return strtoupper($request->server('REQUEST_METHOD')) == 'POST' ? $request->request('scope') : $request->query('scope');
    }

    public function getDefaultScope()
    {
        return $this->storage->getDefaultScope();
    }

    public function getSupportedScopes()
    {
        return $this->storage->getSupportedScopes();
    }
}
