<?php

namespace OAuth2\Storage;

class AccessTokenTest extends BaseTest
{
    /** @dataProvider provideStorage */
    public function testSetAccessToken(AccessTokenInterface $storage)
    {
        if ($storage instanceof NullStorage) {
            $this->markTestSkipped('Skipped Storage: ' . $storage->getMessage());

            return;
        }

        // assert token we are about to add does not exist
        $token = $storage->getAccessToken('newtoken');
        $this->assertFalse($token);

        // add new token
        $expires = time() + 20;
        $success = $storage->setAccessToken('newtoken', 'client ID', 'SOMEUSERID', $expires);
        $this->assertTrue($success);

        $token = $storage->getAccessToken('newtoken');
        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
        $this->assertArrayHasKey('client_id', $token);
        $this->assertArrayHasKey('user_id', $token);
        $this->assertArrayHasKey('expires', $token);
        $this->assertEquals($token['access_token'], 'newtoken');
        $this->assertEquals($token['client_id'], 'client ID');
        $this->assertEquals($token['user_id'], 'SOMEUSERID');
        $this->assertEquals($token['expires'], $expires);

        // change existing token
        $expires = time() + 42;
        $success = $storage->setAccessToken('newtoken', 'client ID2', 'SOMEOTHERID', $expires);
        $this->assertTrue($success);

        $token = $storage->getAccessToken('newtoken');
        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
        $this->assertArrayHasKey('client_id', $token);
        $this->assertArrayHasKey('user_id', $token);
        $this->assertArrayHasKey('expires', $token);
        $this->assertEquals($token['access_token'], 'newtoken');
        $this->assertEquals($token['client_id'], 'client ID2');
        $this->assertEquals($token['user_id'], 'SOMEOTHERID');
        $this->assertEquals($token['expires'], $expires);
    }
}
