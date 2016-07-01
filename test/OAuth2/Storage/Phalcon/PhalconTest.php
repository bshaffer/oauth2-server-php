<?php
/**
 * Created by PhpStorm.
 * User: lucas
 * Date: 7/1/2016
 * Time: 2:08 PM
 */

namespace OAuth2\Storage\Phalcon;


use OAuth2\Storage\BaseTest;
use Phalcon\Mvc\Micro;

class PhalconTest extends BaseTest
{
    public function testGetClientDetails(){
        $app = new Micro();
        $storage = new Phalcon($app->getDI());

        $this->assertNotNull($storage->getClientDetails('oauth_test_client'));
    }

}