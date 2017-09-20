<?php
namespace OAuth2\Storage;

class MongoDB extends KeyValueAbstract
{

    protected $db;

    public function __construct($connection, array $config = array())
    {
        if (!extension_loaded('mongodb')) {
            throw new \LogicException('mongodb extension not loaded');
        }
        
        if ($connection instanceof \MongoDB\Driver\Manager) {
            $this->db = $connection;
        } elseif (is_array($connection)) {
            $server = sprintf('mongodb://%s:%d', $connection['host'], $connection['port']);
            $this->db = new \MongoDB\Driver\Manager($server);
        } else {
            throw new \InvalidArgumentException('First argument to ' . __CLASS__ . ' must be an instance of MongoDB\Driver\Manager or a configuration array');
        }
        
        $this->config = array_merge($this->config, array(
            'database' => $connection['database'],
        ), $config);
    }

    public function get($table, $key)
    {
        try {
            $query = new \MongoDB\Driver\Query(array('_id' => $key), array('limit' => 1));
            $cursor = $this->db->executeQuery("{$this->config['database']}.{$this->config[$table]}", $query);
            $data = $cursor->toArray();
            
            if (isset($data[0])) {
                return $data[0]->value;
            }
            
            return null;
        } catch (\MongoDB\Driver\Exception\Exception $ex) {
        }
        
        return false;
    }

    public function set($table, $key, $value)
    {
        try {
            $bulk = new \MongoDB\Driver\BulkWrite();
            $bulk->update(array('_id' => $key), array('$set' => array('value' => $value)), array('upsert' => true, 'limit' => 1));
            $result = $this->db->executeBulkWrite("{$this->config['database']}.{$this->config[$table]}", $bulk);
            return true;
        } catch (\MongoDB\Driver\Exception\Exception $ex) {
        }
        
        return false;
    }

    public function delete($table, $key)
    {
        try {
            $bulk = new \MongoDB\Driver\BulkWrite();
            $bulk->delete(array('_id' => $key), array('limit' => 1));
            $result = $this->db->executeBulkWrite("{$this->config['database']}.{$this->config[$table]}", $bulk);
            return true;
        } catch (\MongoDB\Driver\Exception\Exception $ex) {
        }
        
        return false;
    }
}
