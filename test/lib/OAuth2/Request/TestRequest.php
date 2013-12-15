<?php

namespace OAuth2\Request;

use OAuth2\RequestInterface;

/**
*
*/
class TestRequest implements RequestInterface
{
    public $query, $request, $server, $headers;

    public function __construct()
    {
        $this->query = $_GET;
        $this->request = $_POST;
        $this->server  = $_SERVER;
    }

    public function query($name, $default = null)
    {
        return isset($this->query[$name]) ? $this->query[$name] : $default;
    }

    public function request($name, $default = null)
    {
        return isset($this->request[$name]) ? $this->request[$name] : $default;
    }

    public function server($name, $default = null)
    {
        return isset($this->server[$name]) ? $this->server[$name] : $default;
    }

    public function headers($name, $default = null)
    {
        return isset($this->headers[$name]) ? $this->headers[$name] : $default;
    }

    public function getAllQueryParameters()
    {
        return $this->query;
    }

    public function setQuery(array $query)
    {
        $this->query = $query;
    }

    public function setPost(array $params)
    {
        $this->server['REQUEST_METHOD'] = 'POST';
        $this->request = $params;
    }

    public static function createPost(array $params = array())
    {
        $request = new self();
        $request->setPost($params);

        return $request;
    }
}
