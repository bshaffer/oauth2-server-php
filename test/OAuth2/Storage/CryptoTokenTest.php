<?php

namespace OAuth2\Storage;

use OAuth2\Encryption\Jwt;

class CryptoTokenTest extends BaseTest
{
    /** @dataProvider provideStorage */
    public function testSetAccessToken($storage)
    {
        $publicKeyStorage = Bootstrap::getInstance()->getMemoryStorage();
        $encryptionUtil = new Jwt();

        $cryptoToken = array(
            'access_token' => rand(),
            'expires' => time() + 100,
            'scope'   => 'foo',
        );

        $token = $encryptionUtil->encode($cryptoToken, $publicKeyStorage->getPrivateKey(), $publicKeyStorage->getEncryptionAlgorithm());

        $this->assertNotNull($token);

        $tokenData = $storage->getAccessToken($token);

        $this->assertTrue(is_array($tokenData));

        /* assert the decoded token is the same */
        $this->assertEquals($tokenData['access_token'], $cryptoToken['access_token']);
        $this->assertEquals($tokenData['expires'], $cryptoToken['expires']);
        $this->assertEquals($tokenData['scope'], $cryptoToken['scope']);
    }

    // @TODO - use the BaseTest provideStorage, and add support for storages which omit certain interfaces
    public function provideStorage()
    {
        $memory = Bootstrap::getInstance()->getMemoryStorage();
        $storage = new CryptoToken($memory);

        return array(
            array($storage)
        );
    }
}
