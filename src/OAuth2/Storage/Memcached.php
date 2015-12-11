<?php
namespace OAuth2\Storage;

class Memcached extends KeyValueAbstract
{

    protected $db;

    public function __construct($connection, $config = array())
    {
        if (!extension_loaded('memcached')) {
            throw new \LogicException('memcached extension not loaded');
        }
        
        if ($connection instanceof \Memcached) {
            $this->db = $connection;
        } else if (is_array($connection) && isset($connection['servers']) && is_array($connection['servers'])) {
            $this->db = new \Memcached();
            $this->db->addServers($connection['servers']);
            if (isset($connection['options']) && is_array($connection['options'])) {
                $this->db->setOptions($connection['options']);
            }
        } else {
            throw new \InvalidArgumentException('First argument to OAuth2\Storage\Memcached must be an instance of Memcached or a configuration array containing a servers array');
        }
        
        $this->config = array_merge($this->config, $config);
    }

    protected function _makeKey($table, $key)
    {
        return $table . '-' . $key;
    }

    public function get($table, $key)
    {
        return $this->db->get($this->_makeKey($table, $key));
    }

    public function set($table, $key, $value)
    {
        return $this->db->set($this->_makeKey($table, $key), $value);
    }

    public function delete($table, $key)
    {
        return $this->db->delete($this->_makeKey($table, $key));
    }
}
