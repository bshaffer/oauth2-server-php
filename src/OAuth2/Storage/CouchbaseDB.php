<?php
namespace OAuth2\Storage;

class CouchbaseDB extends KeyValueAbstract
{

    protected $db;

    public function __construct($connection, $config = array())
    {
        if ($connection instanceof \Couchbase) {
            $this->db = $connection;
        } else if (is_array($connection) && isset($connection['servers']) && is_array($connection['servers'])) {
            $this->db = new \Couchbase($connection['servers'], (isset($connection['username']) ? $connection['username'] : ''), (isset($connection['password']) ? $connection['password'] : ''), $connection['bucket'], false);
        } else {
            throw new \InvalidArgumentException('First argument to ' . __CLASS__ . ' must be an instance of Couchbase or a configuration array containing a servers array');
        }
        
        $this->config = array_merge($this->config, $config);
    }

    protected function _makeKey($table, $key)
    {
        return $table . '-' . $key;
    }

    public function get($table, $key)
    {
        return json_decode($this->db->get($this->_makeKey($table, $key)), true);
    }

    public function set($table, $key, $value)
    {
        return $this->db->set($this->_makeKey($table, $key), json_encode($value));
    }

    public function delete($table, $key)
    {
        return $this->db->delete($this->_makeKey($table, $key), '', 1);
    }
}
