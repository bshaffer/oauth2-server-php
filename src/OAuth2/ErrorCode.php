<?php

namespace OAuth2;

/**
 * OAUth2_ErrorCode
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-3.2.1
 * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-10#section-4.3.1
 */
class ErrorCode
{
    const INVALID_REQUEST           = 'invalid_request';
    const INVALID_CLIENT            = 'invalid_client';
    const UNAUTHORIZED_CLIENT       = 'unauthorized_client';
    const INVALID_GRANT             = 'invalid_grant';
    const UNSUPPORTED_GRANT_TYPE    = 'unsupported_grant_type';
    const INVALID_SCOPE             = 'invalid_scope';
    const REDIRECT_URI_MISMATCH     = 'redirect_uri_mismatch';
    const INVALID_URI               = 'invalid_uri';
    const UNSUPPORTED_RESPONSE_TYPE = 'unsupported_response_type';
}
