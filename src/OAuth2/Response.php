<?php

/**
*
*/
class OAuth2_Response
{
    public $version;
    protected $statusCode = 200;
    protected $statusText;
    protected $parameters = array();
    protected $httpHeaders = array();

    public static $statusTexts = array(
        100 => 'Continue',
        101 => 'Switching Protocols',
        200 => 'OK',
        201 => 'Created',
        202 => 'Accepted',
        203 => 'Non-Authoritative Information',
        204 => 'No Content',
        205 => 'Reset Content',
        206 => 'Partial Content',
        300 => 'Multiple Choices',
        301 => 'Moved Permanently',
        302 => 'Found',
        303 => 'See Other',
        304 => 'Not Modified',
        305 => 'Use Proxy',
        307 => 'Temporary Redirect',
        400 => 'Bad Request',
        401 => 'Unauthorized',
        402 => 'Payment Required',
        403 => 'Forbidden',
        404 => 'Not Found',
        405 => 'Method Not Allowed',
        406 => 'Not Acceptable',
        407 => 'Proxy Authentication Required',
        408 => 'Request Timeout',
        409 => 'Conflict',
        410 => 'Gone',
        411 => 'Length Required',
        412 => 'Precondition Failed',
        413 => 'Request Entity Too Large',
        414 => 'Request-URI Too Long',
        415 => 'Unsupported Media Type',
        416 => 'Requested Range Not Satisfiable',
        417 => 'Expectation Failed',
        418 => 'I\'m a teapot',
        500 => 'Internal Server Error',
        501 => 'Not Implemented',
        502 => 'Bad Gateway',
        503 => 'Service Unavailable',
        504 => 'Gateway Timeout',
        505 => 'HTTP Version Not Supported',
    );

    public function __construct($parameters = array(), $statusCode = 200, $headers = array())
    {
        $this->setParameters($parameters);
        $this->setStatusCode($statusCode);
        $this->setHttpHeaders($headers);
        $this->version = '1.1';
    }

    /**
     * Converts the response object to string containing all headers and the response content.
     *
     * @return string The response with headers and content
     */
    public function __toString()
    {
        $headers = array();
        foreach ($this->httpHeaders as $name => $value) {
            $headers[$name] = (array) $value;
        }

        return
            sprintf('HTTP/%s %s %s', $this->version, $this->statusCode, $this->statusText)."\r\n".
            $this->getHttpHeadersAsString($headers)."\r\n".
            $this->getResponseBody();
    }

    /**
     * Returns the build header line.
     *
     * @param string $name  The header name
     * @param string $value The header value
     *
     * @return string The built header line
     */
    protected function buildHeader($name, $value)
    {
        return sprintf("%s: %s\n", $name, $value);
    }

    public function getStatusCode()
    {
        return $this->statusCode;
    }

    public function setStatusCode($statusCode, $text = null)
    {
        $this->statusCode = (int) $statusCode;
        if ($this->isInvalid()) {
            throw new InvalidArgumentException(sprintf('The HTTP status code "%s" is not valid.', $statusCode));
        }

        $this->statusText = false === $text ? '' : (null === $text ? self::$statusTexts[$this->statusCode] : $text);
    }

    public function getStatusText()
    {
        return $this->statusText;
    }

    public function getParameters()
    {
        return $this->parameters;
    }

    public function setParameters($parameters)
    {
        $this->parameters = $parameters;
    }
    public function getParameter($name, $default = null)
    {
        return isset($this->parameters[$name]) ? $this->parameters[$name] : $default;
    }

    public function setParameter($name, $value)
    {
        $this->parameters[$name] = $value;
    }

    public function setHttpHeaders($httpHeaders)
    {
        $this->httpHeaders = $httpHeaders;
    }

    public function setHttpHeader($name, $value)
    {
        $this->httpHeaders[$name] = $value;
    }

    public function getHttpHeaders()
    {
        return $this->httpHeaders;
    }

    public function getHttpHeader($name, $default = null)
    {
        return isset($this->httpHeaders[$name]) ? $this->httpHeaders[$name] : $default;
    }

    public function getResponseBody($format = 'json')
    {
        switch ($format) {
            case 'json':
                return json_encode($this->parameters);
            case 'xml':
                // this only works for single-level arrays
                $xml = new SimpleXMLElement('<response/>');
                array_walk($this->parameters, array($xml, 'addChild'));
                return $xml->asXML();
        }

        throw new InvalidArgumentException(sprintf('The format %s is not supported'));

    }

    public function send($format = 'json')
    {
        // headers have already been sent by the developer
        if (headers_sent()) {
            return;
        }

        switch ($format) {
            case 'json':
                $this->setHttpHeader('Content-Type', 'application/json');
                break;
            case 'xml':
                $this->setHttpHeader('Content-Type', 'text/xml');
                break;
        }
        // status
        header(sprintf('HTTP/%s %s %s', $this->version, $this->statusCode, $this->statusText));

        foreach ($this->getHttpHeaders() as $name => $header) {
            header(sprintf('%s: %s', $name, $header));
        }
        echo $this->getResponseBody($format);
    }

// http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
    /**
     * @return Boolean
     *
     * @api
     */
    public function isInvalid()
    {
        return $this->statusCode < 100 || $this->statusCode >= 600;
    }

    /**
     * @return Boolean
     *
     * @api
     */
    public function isInformational()
    {
        return $this->statusCode >= 100 && $this->statusCode < 200;
    }

    /**
     * @return Boolean
     *
     * @api
     */
    public function isSuccessful()
    {
        return $this->statusCode >= 200 && $this->statusCode < 300;
    }

    /**
     * @return Boolean
     *
     * @api
     */
    public function isRedirection()
    {
        return $this->statusCode >= 300 && $this->statusCode < 400;
    }

    /**
     * @return Boolean
     *
     * @api
     */
    public function isClientError()
    {
        return $this->statusCode >= 400 && $this->statusCode < 500;
    }

    /**
     * @return Boolean
     *
     * @api
     */
    public function isServerError()
    {
        return $this->statusCode >= 500 && $this->statusCode < 600;
    }

    /*
     * Functions from Symfony2 HttpFoundation - output pretty header
     */
    private function getHttpHeadersAsString($headers)
    {
        if (count($headers) == 0) {
            return '';
        }
        $max = max(array_map('strlen', array_keys($headers))) + 1;
        $content = '';
        ksort($headers);
        foreach ($headers as $name => $values) {
            foreach ($values as $value) {
                $content .= sprintf("%-{$max}s %s\r\n", $this->beautifyHeaderName($name).':', $value);
            }
        }

        return $content;
    }

    private function beautifyHeaderName($name)
    {
        return preg_replace_callback('/\-(.)/', array($this, 'beautifyCallback'), ucfirst($name));
    }

    private function beautifyCallback($match)
    {
        return '-'.strtoupper($match[1]);
    }
}
