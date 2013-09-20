<?php

namespace OAuth2\Storage;

class CryptoTokenTest extends BaseTest
{
    /** @dataProvider provideStorage */
    public function testSetAccessToken(CryptoTokenInterface $storage = null)
    {
        $cryptoToken = array(
            'access_token' => rand(),
            'expires' => time() + 100,
            'scope'   => 'foo',
        );
        $token = $storage->encodeToken($cryptoToken);

        $this->assertNotNull($token);

        $decodedToken = $storage->getAccessToken($token);

        $this->assertTrue(is_array($decodedToken));

        /* assert the decoded token is the same */
        $this->assertEquals($decodedToken['access_token'], $cryptoToken['access_token']);
        $this->assertEquals($decodedToken['expires'], $cryptoToken['expires']);
        $this->assertEquals($decodedToken['scope'], $cryptoToken['scope']);
    }

    public function provideStorage()
    {
        $publicKeyStorage = Bootstrap::getPublicKeyStorage();

        return array(
            array($publicKeyStorage)
        );
    }
}
