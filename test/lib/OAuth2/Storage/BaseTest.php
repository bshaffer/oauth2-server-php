<?php

namespace OAuth2\Storage;

abstract class BaseTest extends \PHPUnit_Framework_TestCase
{
    public function provideStorage()
    {
        if (!$mysql = Bootstrap::getInstance()->getMysqlPdo()) {
            $mysql = new NullStorage('MySQL');
        }

        if (!$sqlite = Bootstrap::getInstance()->getSqlitePdo()) {
            $sqlite = new NullStorage('SQLite');
        }

        if (!$mongo = Bootstrap::getInstance()->getMongo()) {
            $mongo = new NullStorage('MongoDB');
        }

        if (!$redis = Bootstrap::getInstance()->getRedisStorage()) {
            $redis = new NullStorage('Redis');
        }

        if (!$cassandra = Bootstrap::getInstance()->getCassandraStorage()) {
            $cassandra = new NullStorage('Cassandra');
        }

        /* hack until we can fix "default_scope" dependencies in other tests */
        // $memory = Bootstrap::getInstance()->getMemoryStorage();
        $memoryConfig = json_decode(file_get_contents(__DIR__.'/../../../config/storage.json'), true);
        $memoryConfig['default_scope'] = 'defaultscope1 defaultscope2';
        $memory = new Memory($memoryConfig);

        // will add multiple storage types later
        return array(
            array($memory),
            array($sqlite),
            array($mysql),
            array($mongo),
            array($redis),
            array($cassandra),
        );
    }
}
