<?php

namespace OAuth2;

interface RequestInterface
{
    public function query($name, $default = null);

    public function request($name, $default = null);

    public function server($name, $default = null);

    public function headers($name, $default = null);

    public function getAllQueryParameters();
}
