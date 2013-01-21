<?php

/**
*
*/
class OAuth2_Response_Redirect extends OAuth2_Response
{
    public function __construct($url, $statusCode = 302, $error = null, $errorDescription = null, $state = null)
    {
        if (empty($url)) {
            throw new InvalidArgumentException('Cannot redirect to an empty URL.');
        }

        $query = array();

        if (!is_null($error)) {
            $query['error'] = $error;
        }

        if (!is_null($errorDescription)) {
            $query['error_description'] = $errorDescription;
        }

        if (!is_null($state)) {
            $query['state'] = $state;
        }

        if (count($query) > 0) {
            $parts = parse_url($url);
            $sep = isset($parts['query']) && count($parts['query']) > 0 ? '&' : '?';
            $url = $url . $sep . http_build_query($query);
        }

        $httpHeaders = array(
            'Location' =>  $url,
        );

        parent::__construct(array(), $statusCode, $httpHeaders);

        if (!$this->isRedirection()) {
            throw new InvalidArgumentException(sprintf('The HTTP status code is not a redirect ("%s" given).', $statusCode));
        }
    }
}
