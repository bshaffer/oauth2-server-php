<?php

namespace OAuth2;

class AutoloadTest extends \PHPUnit_Framework_TestCase
{
    public function testClassesExist()
    {
        // autoloader is called in test/bootstrap.php
        $this->assertTrue(class_exists('OAuth2\Server'));
        $this->assertTrue(class_exists('OAuth2\Request'));
        $this->assertTrue(class_exists('OAuth2\Response'));
        $this->assertTrue(class_exists('OAuth2\GrantType\UserCredentials'));
        $this->assertTrue(interface_exists('OAuth2\Storage\AccessTokenInterface'));
    }
}
