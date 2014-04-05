<?php

namespace OAuth2\Storage;

abstract class BaseTest extends \PHPUnit_Framework_TestCase
{
    public function provideStorage()
    {
        $mysql = Bootstrap::getInstance()->getMysqlPdo();
        $postgres = Bootstrap::getInstance()->getPostgresPdo();
        $sqlite = Bootstrap::getInstance()->getSqlitePdo();
        $mongo = Bootstrap::getInstance()->getMongo();
        $redis = Bootstrap::getInstance()->getRedisStorage();
        $cassandra = Bootstrap::getInstance()->getCassandraStorage();
        $memory = Bootstrap::getInstance()->getMemoryStorage();

        /* hack until we can fix "default_scope" dependencies in other tests */
        $memory->defaultScope = 'defaultscope1 defaultscope2';

        return array(
            array($memory),
            array($sqlite),
            array($mysql),
            array($postgres),
            array($mongo),
            array($redis),
            array($cassandra),
        );
    }
}
