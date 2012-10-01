<?php

class OAuth2_AutoloadTest extends PHPUnit_Framework_TestCase
{
    public function testClassesExist()
    {
        // autoloader is called in test/bootstrap.php
        $this->assertTrue(class_exists('OAuth2_Server'));
        $this->assertTrue(class_exists('OAuth2_Request'));
        $this->assertTrue(class_exists('OAuth2_Response'));
        $this->assertTrue(class_exists('OAuth2_GrantType_UserCredentials'));
        $this->assertTrue(interface_exists('OAuth2_Storage_AccessTokenInterface'));
    }
}