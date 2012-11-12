<?php

/**
*
*/
class OAuth2_Request_TestRequest implements OAuth2_RequestInterface
{
    private $query, $post, $server;

    public function __construct()
    {
        $this->query = $_GET;
        $this->post = $_POST;
        $this->server  = $_SERVER;
    }

    public function query($name, $default = null)
    {
        return isset($this->query[$name]) ? $this->query[$name] : $default;
    }

    public function request($name, $default = null)
    {
        return isset($this->post[$name]) ? $this->post[$name] : $default;
    }

    public function server($name, $default = null)
    {
        return isset($this->server[$name]) ? $this->server[$name] : $default;
    }

    public function headers($name, $default = null)
    {
        return $default;
    }

    public function getAllQueryParameters()
    {
        return $this->query;
    }

    public function setQuery(array $query)
    {
        $this->query = $query;
    }
}