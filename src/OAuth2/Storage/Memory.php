<?php
namespace OAuth2\Storage;

class Memory extends KeyValueAbstract
{

    protected $oauth_clients = array();

    protected $oauth_access_tokens = array();

    protected $oauth_refresh_tokens = array();

    protected $oauth_authorization_codes = array();

    protected $oauth_users = array();

    protected $oauth_jwt = array();

    protected $oauth_jti = array();

    protected $oauth_scopes = array();

    protected $oauth_public_keys = array();

    public function __construct($params = array())
    {
        if (isset($params['authorization_codes']) && is_array($params['authorization_codes'])) {
            foreach ($params['authorization_codes'] as $key => $val) {
                $val['authorization_code'] = $key;
                $this->oauth_authorization_codes[$key] = $val;
            }
        }
        
        if (isset($params['client_credentials']) && is_array($params['client_credentials'])) {
            foreach ($params['client_credentials'] as $key => $val) {
                $val['client_id'] = $key;
                $this->oauth_clients[$key] = $val;
            }
        }
        
        if (isset($params['user_credentials']) && is_array($params['user_credentials'])) {
            foreach ($params['user_credentials'] as $key => $val) {
                $val['username'] = $key;
                $this->oauth_users[$key] = $val;
            }
        }
        
        if (isset($params['refresh_tokens']) && is_array($params['refresh_tokens'])) {
            foreach ($params['refresh_tokens'] as $key => $val) {
                $val['refresh_token'] = $key;
                $this->oauth_refresh_tokens[$key] = $val;
            }
        }
        
        if (isset($params['access_tokens']) && is_array($params['access_tokens'])) {
            foreach ($params['access_tokens'] as $key => $val) {
                $val['access_token'] = $key;
                $this->oauth_access_tokens[$key] = $val;
            }
        }
        
        if (isset($params['jwt']) && is_array($params['jwt'])) {
            foreach ($params['jwt'] as $key => $val) {
                $this->setClientKey($key, $val['key'], $val['subject']);
            }
        }
        
        if (isset($params['jti']) && is_array($params['jti'])) {
            foreach ($params['jti'] as $key => $val) {
                $this->setJti($val['issuer'], $val['subject'], $val['audience'], $val['expires'], $val['jti']);
            }
        }
        
        if (isset($params['supported_scopes']) && is_array($params['supported_scopes'])) {
            $this->setScope(implode(' ', $params['supported_scopes']), null, self::KEY_SUPPORTED);
        }
        if (isset($params['default_scope']) && is_string($params['default_scope'])) {
            $this->setScope($params['default_scope'], null, self::KEY_DEFAULT);
        }
        
        if (isset($params['keys']) && is_array($params['keys'])) {
            if (isset($params['keys']['private_key'])) {
                $private_key = $params['keys']['private_key'];
                $public_key = isset($params['keys']['public_key']) ? $params['keys']['public_key'] : null;
                $encryption_algorithm = isset($params['keys']['encryption_algorithm']) ? $params['keys']['encryption_algorithm'] : 'RS256';
                $this->setServerKey(null, $public_key, $private_key, $encryption_algorithm);
            }
            unset($params['keys']['private_key']);
            unset($params['keys']['public_key']);
            unset($params['keys']['encryption_algorithm']);
            
            foreach ($params['keys'] as $key => $val) {
                $this->setServerKey($key, $val['public_key'], $val['private_key'], $val['encryption_algorithm']);
            }
        }
    }

    public function get($table, $key)
    {
        return isset($this->$table[$key]) ? $this->$table[$key] : null;
    }

    public function set($table, $key, $value)
    {
        $this->$table[$key] = $value;
        return true;
    }

    public function delete($table, $key)
    {
        unset($this->$table[$key]);
        return true;
    }
}
