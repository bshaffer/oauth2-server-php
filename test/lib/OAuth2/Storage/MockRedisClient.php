<?php

namespace OAuth2\Storage;

class MockRedisClient
{
    public function __construct()
    {
        $data = array(
            'oauth_clients:oauth_test_client' => array(
                'client_id' => 'oauth_test_client',
                'client_secret' => "testpass",
                'redirect_uri' => '',
                'grant_types' => 'implicit password',
            ),
            'oauth_clients:Test Client ID' => array(
                'client_id' => 'Test Client ID',
                'client_secret' => "TestSecret",
                'supported_scopes' => 'clientscope1 clientscope2',
                'default_scope' => 'clientscope1 clientscope2',
            ),
            'oauth_clients:Test Client ID 2' => array(
                'client_id' => 'Test Client ID 2',
                'client_secret' => "TestSecret",
                'supported_scopes' => 'clientscope3',
                'default_scope' => 'clientscope3',
            ),
            'oauth_clients:Test Default Scope Client ID' => array(
                'client_id' => 'Test Default Scope Client ID',
                'client_secret' => "TestSecret",
                'supported_scopes' => 'clientscope1 clientscope2',
                'default_scope' => 'clientscope1 clientscope2',
            ),
            'oauth_clients:Test Default Scope Client ID 2' => array(
                'client_id' => 'Test Default Scope Client ID 2',
                'client_secret' => "TestSecret",
                'supported_scopes' => 'clientscope3',
                'default_scope' => 'clientscope3',
            ),
            'oauth_access_tokens:testtoken' => array(
                'access_token' => 'testtoken',
                'client_id' => "Some Client",
                'user_id' => '',
                'expires' => 0,
                'scope' => ''
            ),
            'oauth_authorization_codes:testcode' => array(
                'client_id' => "Some Client",
                'authorization_code' => 'testcode',
                'user_id' => '',
                'redirect_uri' => '',
                'expires' => 0,
                'scope' => ''
            ),
            'oauth_users:testuser' => array(
                'user_id' => 'testuser',
                'password' => "password",
                'first_name' => '',
                'last_name' => ''
            )
        );
        foreach ( $data as $name => $val ) {
            $data[$name] = json_encode($val);
        }
        $this->data = $data;
    }

    function get($key)
    {
        return isset($this->data[$key]) ? $this->data[$key] : null;
    }

    function set ($key, $value)
    {
        $this->data[$key] = $value;
        return true;
    }

    function setex($key, $expires, $value)
    {

        $this->data[$key] = $value;
        return true;
    }

    function expire($key)
    {
        unset($this->data[$key]);
        return true;
    }
}
