<?php

namespace OAuth2\Request;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Zend\Diactoros\Request;
use Zend\Diactoros\Stream;

/**
*
*/
class TestRequest extends Request implements RequestInterface
{
    public function __construct($query = null, $request = null)
    {
        $query = $query ?: $_GET;
        $request = $request ?: $_POST;

        $stream = new Stream('php://temp', 'rw');

        if ($request) {
            $stream->write(json_encode($request));
        }

        parent::__construct(
            'http://localhost/?' . http_build_query($query),
            $request ? 'POST' : 'GET',
            $stream,
            array('Content-Type' => 'application/json')
        );
    }

    public static function createPost(array $params = array())
    {
        return new self(null, $params);
    }
}
