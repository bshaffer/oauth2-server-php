<?php

class OAuth2_Http_StatusCode
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
    const FOUND = '302 Found';
    const BAD_REQUEST = '400 Bad Request';
    const UNAUTHORIZED = '401 Unauthorized';
    const FORBIDDEN = '403 Forbidden';
    const UNAVAILABLE = '503 Service Unavailable';
    
    /**
     * @}
     */
}