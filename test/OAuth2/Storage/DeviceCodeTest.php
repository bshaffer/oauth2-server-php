<?php

namespace OAuth2\Storage;

class DeviceCodeTest extends BaseTest
{
    /** @dataProvider provideStorage */
    public function testSetDeviceCode(DeviceCodeInterface $storage)
    {
        if ($storage instanceof NullStorage) {
            $this->markTestSkipped('Skipped Storage: ' . $storage->getMessage());

            return;
        }

        // assert token we are about to add does not exist
        $code = $storage->getDeviceCode('newcode', 'client_id');
        $this->assertFalse($code);

        // add new token
        $expires = time() + 20;
        $success = $storage->setDeviceCode('newcode', 'user_code', 'client_id', null, $expires);
        $this->assertTrue($success);

        $code = $storage->getDeviceCode('newcode', 'client_id');
        $this->assertNotNull($code);
        $this->assertArrayHasKey('device_code', $code);
        $this->assertArrayHasKey('client_id', $code);
        $this->assertArrayHasKey('user_id', $code);
        $this->assertArrayHasKey('expires', $code);
        $this->assertEquals($code['device_token'], 'newcode');
        $this->assertEquals($code['client_id'], 'client_id');
        $this->assertEquals($code['user_id'], null);
        $this->assertEquals($code['expires'], $expires);

        // change existing token
        $expires = time() + 42;
        $success = $storage->setDeviceCode('newcode', 'user_code', 'client_id', 'user_id', $expires);
        $this->assertTrue($success);

        $code = $storage->getAccessToken('newcode');
        $this->assertNotNull($code);
        $this->assertArrayHasKey('device_code', $code);
        $this->assertArrayHasKey('client_id', $code);
        $this->assertArrayHasKey('user_id', $code);
        $this->assertArrayHasKey('expires', $code);
        $this->assertEquals($code['device_code'], 'newcode');
        $this->assertEquals($code['client_id'], 'client_id');
        $this->assertEquals($code['user_id'], 'user_id');
        $this->assertEquals($code['expires'], $expires);

        // add token with scope having an empty string value
        $expires = time() + 42;
        $success = $storage->setDeviceCode('newcode', 'user_code', 'client_id', 'user_id', $expires, '');
        $this->assertTrue($success);
    }
}
