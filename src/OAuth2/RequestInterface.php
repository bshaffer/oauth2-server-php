<?php

namespace OAuth2;

interface RequestInterface
{
    /**
     * @param string $name
     * @param mixed  $default
     * @return mixed
     */
    public function query(string $name, mixed $default = null);

    /**
     * @param string $name
     * @param mixed  $default
     * @return mixed
     */
    public function request(string $name, mixed $default = null);

    /**
     * @param string $name
     * @param mixed  $default
     * @return mixed
     */
    public function server(string $name, mixed $default = null);

    /**
     * @param string $name
     * @param mixed  $default
     * @return mixed
     */
    public function headers(string $name, mixed $default = null);

    /**
     * @return mixed
     */
    public function getAllQueryParameters(): mixed;
}
