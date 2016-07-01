<?php
/**
 * Created by PhpStorm.
 * User: lucas
 * Date: 7/1/2016
 * Time: 2:08 PM
 */

namespace OAuth2\Storage\Phalcon;


use OAuth2\Storage\BaseTest;
use Phalcon\Db\Adapter\Pdo\Mysql;
use Phalcon\Di\FactoryDefault;
use Phalcon\Mvc\Micro;

class PhalconTest extends BaseTest
{
    public function testGetClientDetails(){
        $di = new FactoryDefault();
        $di->set('db', function() {
            return new Mysql(array(
                "host" => "localhost",
                "username" => "root",
                "password" => "",
                "dbname" => "oauth2_server_php",
            ));
        });
        $app = new Micro($di);
        $storage = new Phalcon($app->getDI());
        $this->assertNotNull($storage->getClientDetails('oauth_test_client'));
    }

}