<?php

namespace OAuth2\Storage;

abstract class BaseTest extends \PHPUnit_Framework_TestCase
{
    public function provideStorage()
    {
        $memory = Bootstrap::getInstance()->getMemoryStorage();
        $sqlite = Bootstrap::getInstance()->getSqlitePdo();
        $mysql = Bootstrap::getInstance()->getMysqlPdo();
        $postgres = Bootstrap::getInstance()->getPostgresPdo();
        $mongo = Bootstrap::getInstance()->getMongo();
        $redis = Bootstrap::getInstance()->getRedisStorage();
        $cassandra = Bootstrap::getInstance()->getCassandraStorage();
        $dynamodb = Bootstrap::getInstance()->getDynamoDbStorage();
        $couchbase = Bootstrap::getInstance()->getCouchbase();

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
            array($dynamodb),
            array($couchbase),
        );
    }
}
