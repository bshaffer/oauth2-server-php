<?php

namespace OAuth2\Storage;

abstract class BaseTest extends \PHPUnit_Framework_TestCase
{
    public function provideStorage()
    {
        $mysql = Bootstrap::getInstance()->getMysqlPdo();
        $sqlite = Bootstrap::getInstance()->getSqlitePdo();
        $mongo = Bootstrap::getInstance()->getMongo();
        $redis = Bootstrap::getInstance()->getRedisStorage();

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
            array($redis)
        );
    }
}
