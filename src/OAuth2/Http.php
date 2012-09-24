<?php

abstract class OAuth2_Http
{
    /**
     * @defgroup self::HTTP_status HTTP status code
     * @{
     */

    /**
     * HTTP status codes for successful and error states as specified by draft 20.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     */
    const HTTP_FOUND = '302 Found';
    const HTTP_BAD_REQUEST = '400 Bad Request';
    const HTTP_UNAUTHORIZED = '401 Unauthorized';
    const HTTP_FORBIDDEN = '403 Forbidden';
    const HTTP_UNAVAILABLE = '503 Service Unavailable';
    
    /**
     * @}
     */
     
    /**
     * @defgroup oauth2_error Error handling
     * @{
     *
     * @todo Extend for i18n.
     * @todo Consider moving all error related functionality into a separate class.
     */
    
    /**
     * The request is missing a required parameter, includes an unsupported
     * parameter or parameter value, or is otherwise malformed.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     */
    const ERROR_INVALID_REQUEST = 'invalid_request';
    
    /**
     * The client identifier provided is invalid.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     */
    const ERROR_INVALID_CLIENT = 'invalid_client';
    
    /**
     * The client is not authorized to use the requested response type.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     */
    const ERROR_UNAUTHORIZED_CLIENT = 'unauthorized_client';
    
    /**
     * The redirection URI provided does not match a pre-registered value.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-3.1.2.4
     */
    const ERROR_REDIRECT_URI_MISMATCH = 'redirect_uri_mismatch';
    
    /**
     * The end-user or authorization server denied the request.
     * This could be returned, for example, if the resource owner decides to reject
     * access to the client at a later point.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
     */
    const ERROR_USER_DENIED = 'access_denied';
    
    /**
     * The requested response type is not supported by the authorization server.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
     */
    const ERROR_UNSUPPORTED_RESPONSE_TYPE = 'unsupported_response_type';
    
    /**
     * The requested scope is invalid, unknown, or malformed.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
     */
    const ERROR_INVALID_SCOPE = 'invalid_scope';
    
    /**
     * The provided authorization grant is invalid, expired,
     * revoked, does not match the redirection URI used in the
     * authorization request, or was issued to another client.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     */
    const ERROR_INVALID_GRANT = 'invalid_grant';
    
    /**
     * The authorization grant is not supported by the authorization server.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     */
    const ERROR_UNSUPPORTED_GRANT_TYPE = 'unsupported_grant_type';
    
    /**
     * The request requires higher privileges than provided by the access token.
     * The resource server SHOULD respond with the HTTP 403 (Forbidden) status
     * code and MAY include the "scope" attribute with the scope necessary to
     * access the protected resource.
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.1.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-4.2.2.1
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-5.2
     */
    const ERROR_INSUFFICIENT_SCOPE = 'invalid_scope';

    /**
     * @}
     */
}