<?php

namespace OAuth2\Storage;

use OAuth2\Encryption\Jwt;

class CryptoTokenTest extends BaseTest
{
    /** @dataProvider provideStorage */
    public function testSetAccessToken($storage)
    {
        if (!$storage instanceof PublicKey) {
            // incompatible storage
            return;
        }

        $crypto = new CryptoToken($storage);

        $publicKeyStorage = Bootstrap::getInstance()->getMemoryStorage();
        $encryptionUtil = new Jwt();

        $cryptoToken = array(
            'access_token' => rand(),
            'expires' => time() + 100,
            'scope'   => 'foo',
        );

        $token = $encryptionUtil->encode($cryptoToken, $storage->getPrivateKey(), $storage->getEncryptionAlgorithm());

        $this->assertNotNull($token);

        $tokenData = $crypto->getAccessToken($token);

        $this->assertTrue(is_array($tokenData));

        /* assert the decoded token is the same */
        $this->assertEquals($tokenData['access_token'], $cryptoToken['access_token']);
        $this->assertEquals($tokenData['expires'], $cryptoToken['expires']);
        $this->assertEquals($tokenData['scope'], $cryptoToken['scope']);
    }
}
