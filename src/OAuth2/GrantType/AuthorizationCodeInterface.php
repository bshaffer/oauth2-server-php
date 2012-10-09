<?php

interface OAuth2_GrantType_AuthorizationCodeInterface extends OAuth2_GrantTypeInterface
{
    /**
     * @return
     * TRUE if the grant type requires a redirect_uri, FALSE if not
     */
    public function enforceRedirect();
}

