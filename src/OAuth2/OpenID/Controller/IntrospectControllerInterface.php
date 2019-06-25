<?php
/**
* Introspection
* Author B.Degoy 2019/06/21...
*/

namespace OAuth2\OpenID\Controller;

use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;

/**
 *  This controller is called when the user claims for OpenID Connect's ID Token verification.
 *
 * @code
 *     $response = new OAuth2\Response();
 *     $IntrospectController->handleIntrospectRequest(
 *         OAuth2\Request::createFromGlobals(),
 *         $response
 *     );
 *     $response->send();
 * @endcode
 */
interface IntrospectControllerInterface
{
    /**
     * Handle user info request
     *
     * @param RequestInterface $request
     * @param ResponseInterface $response
     */
    public function handleIntrospectRequest(RequestInterface $request, ResponseInterface $response);
}
