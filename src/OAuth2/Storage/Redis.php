<?php
namespace OAuth2\Storage;

class Redis extends KeyValueAbstract
{
    private $cache;
    protected $db;

    public function __construct($connection = array(), array $config = array())
    {
        if ($connection instanceof \Predis\Client) {
            $this->db = $connection;
        } else if (is_array($connection)) {
            $connection = array_merge(array(
                'parameters' => null,
                'options'    => null,
            ), $connection);
            
            $this->db = new \Predis\Client($connection['parameters'], $connection['options']);
        } else {
            throw new \InvalidArgumentException('First argument to ' . __CLASS__ . ' must be an instance of Predis\Client or a configuration array');
        }
        
        $this->config = array_merge($this->config, array(
            'expire' => 0,
        ), $config);
    }

    protected function _makeKey($table, $key)
    {
        return $table . ':' . $key;
    }

    protected function get($table, $key)
    {
        $key = $this->_makeKey($table, $key);
        
        if (isset($this->cache[$key])) {
            return $this->cache[$key];
        }
        
        $value = $this->db->get($key);
        if (isset($value)) {
            return json_decode($value, true);
        }
        
        return false;
    }

    protected function set($table, $key, $value)
    {
        $key = $this->_makeKey($table, $key);
        
        $this->cache[$key] = $value;
        
        $str = json_encode($value);
        if ($this->config['expire'] > 0) {
            $seconds = $this->config['expire'] - time();
            return (bool)$this->db->setex($key, $seconds, $str);
        } else {
            return (bool)$this->db->set($key, $str);
        }
        
        return false;
    }

    protected function delete($table, $key)
    {
        $key = $this->_makeKey($table, $key);
        
        unset($this->cache[$key]);
        
        return $this->db->del($key);
    }
}
