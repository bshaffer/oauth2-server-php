<?php

namespace OAuth2\Storage;

use phpcassa\ColumnFamily;
use phpcassa\Connection\ConnectionPool;

class Cassandra extends KeyValueAbstract
{
    private $cache;

    protected $db;

    /**
     * Cassandra Storage! uses phpCassa
     *
     * @param \phpcassa\Connection\ConnectionPool|array $connection
     * @param array $config
     */
    public function __construct($connection = array(), array $config = array())
    {
        if ($connection instanceof ConnectionPool) {
            $this->db = $connection;
        } else if (is_array($connection)) {
            $connection = array_merge(array(
                'keyspace' => 'oauth2',
                'servers'  => null,
            ), $connection);
            
            $this->db = new ConnectionPool($connection['keyspace'], $connection['servers']);
        } else {
            throw new \InvalidArgumentException('First argument to ' . __CLASS__ . ' must be an instance of phpcassa\Connection\ConnectionPool or a configuration array');
        }
        
        $this->config = array_merge($this->config, array(
            'column_family' => 'auth',
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
        $cf = new ColumnFamily($this->db, $this->config['column_family']);
        
        try {
            $value = $cf->get($key, new \phpcassa\ColumnSlice("", ""));
            return json_decode(current($value), true);
        } catch (\Exception $e) {
            
        }
        
        return false;
    }

    protected function set($table, $key, $value)
    {
        $key = $this->_makeKey($table, $key);
        
        $this->cache[$key] = $value;
        
        $cf = new ColumnFamily($this->db, $this->config['column_family']);
        
        $str = json_encode($value);
        try {
            $cf->insert($key, array('__data' => $str), null, ($this->config['expire'] > 0 ? $this->config['expire'] - time() : null));
            return true;
        } catch (\Exception $e) {
        }
        
        return false;
    }

    protected function delete($table, $key)
    {
        $key = $this->_makeKey($table, $key);
        
        unset($this->cache[$key]);
        
        $cf = new ColumnFamily($this->db, $this->config['column_family']);
        try {
            // __data key set as C* requires a field
            $cf->remove($key, array('__data'));
            return true;
        } catch (\Exception $e) {
        }
        
        return false;
    }
}
