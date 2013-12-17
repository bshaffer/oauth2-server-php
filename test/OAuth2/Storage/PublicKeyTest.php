<?php

namespace OAuth2\Storage;

class PublicKeyTest extends BaseTest
{
    /** @dataProvider provideStorage */
    public function testSetAccessToken($storage)
    {
        if (is_null($storage) || !$storage instanceof PublicKeyInterface) {
            return $this->markTestSkipped('Invalid storage for public key test');
        }

        $configDir = Bootstrap::getInstance()->getConfigDir();
        $globalPublicKey  = file_get_contents($configDir.'/keys/id_rsa.pub');
        $globalPrivateKey = file_get_contents($configDir.'/keys/id_rsa');

        /* assert values from storage */
        $this->assertEquals($storage->getPublicKey(), $globalPublicKey);
        $this->assertEquals($storage->getPrivateKey(), $globalPrivateKey);
    }
}
