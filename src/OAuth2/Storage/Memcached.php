<?php
namespace OAuth2\Storage;

class Memcached extends KeyValueAbstract
{

    protected $db;

    public function __construct($connection, array $config = array())
    {
        if (!extension_loaded('memcached')) {
            throw new \LogicException('memcached extension not loaded');
        }
        
        if ($connection instanceof \Memcached) {
            $this->db = $connection;
        } elseif (is_array($connection) && isset($connection['servers']) && is_array($connection['servers'])) {
            $this->db = new \Memcached();
            $this->db->addServers($connection['servers']);
            if (isset($connection['options']) && is_array($connection['options'])) {
                $this->db->setOptions($connection['options']);
            }
        } else {
            throw new \InvalidArgumentException('First argument to ' . __CLASS__ . ' must be an instance of Memcached or a configuration array containing a servers array');
        }
        
        $this->config = array_merge($this->config, $config);
    }

    protected function makeKey($table, $key)
    {
        return $table . '-' . $key;
    }

    public function get($table, $key)
    {
        return $this->db->get($this->makeKey($table, $key));
    }

    public function set($table, $key, $value)
    {
        return $this->db->set($this->makeKey($table, $key), $value);
    }

    public function delete($table, $key)
    {
        return $this->db->delete($this->makeKey($table, $key));
    }
}
