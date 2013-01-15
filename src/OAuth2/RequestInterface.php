<?php

interface OAuth2_RequestInterface
{
    public function query($name, $default = null);

    public function request($name, $default = null);

    public function server($name, $default = null);

    public function headers($name, $default = null);

    public function getAllQueryParameters();
}
