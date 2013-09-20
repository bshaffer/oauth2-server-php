<?php

namespace OAuth2\Storage;

use OAuth2\Scope;

class ScopeTest extends BaseTest
{
    /** @dataProvider provideStorage */
    public function testScopeExists($storage = null)
    {
        if (is_null($storage)) {
            $this->markTestSkipped('Unable to load class Mongo_Client');
            return;
        }

        if (!$storage instanceof ScopeInterface) {
            $this->markTestSkipped('Skipping incompatible storage');
            return;
        }

        //Test getting scopes with a client_id
        $scopeUtil = new Scope($storage);
        $this->assertTrue($scopeUtil->scopeExists('clientscope1 clientscope2', 'Test Client ID'));
        $this->assertFalse($scopeUtil->scopeExists('clientscope1 clientscope2 clientscope3', 'Test Client ID'));
        $this->assertTrue($scopeUtil->scopeExists('clientscope3', 'Test Client ID 2'));
    }

    /** @dataProvider provideStorage */
    public function testGetDefaultScope($storage = null)
    {
        if (is_null($storage)) {
            $this->markTestSkipped('Unable to load class Mongo_Client');
            return;
        }

        if (!$storage instanceof ScopeInterface) {
            $this->markTestSkipped('Skipping incompatible storage');
            return;
        }

        // test getting default scope
        $scopeUtil = new Scope($storage);
        $this->assertEquals($scopeUtil->getDefaultScope(), 'defaultscope1 defaultscope2');
    }

    /** @dataProvider provideStorage */
    public function testClientScopeExists($storage = null)
    {
        if (is_null($storage)) {
            $this->markTestSkipped('Unable to load class Mongo_Client');
            return;
        }

        if (!$storage instanceof ScopeInterface) {
            $this->markTestSkipped('Skipping incompatible storage');
            return;
        }

        // test getting scopes with a client_id
        $scopeUtil = new Scope($storage);
        $this->assertTrue($scopeUtil->scopeExists('supportedscope1'));
        $this->assertTrue($scopeUtil->scopeExists('supportedscope2'));
        $this->assertTrue($scopeUtil->scopeExists('supportedscope1 supportedscope2'));
        $this->assertFalse($scopeUtil->scopeExists('bogusscope'));
    }

    /** @dataProvider provideStorage */
    public function testGetDefaultClientScope($storage = null)
    {
        if (is_null($storage)) {
            $this->markTestSkipped('Unable to load class Mongo_Client');
            return;
        }

        if (!$storage instanceof ScopeInterface) {
            $this->markTestSkipped('Skipping incompatible storage');
            return;
        }

        // test getting scopes with a client_id
        $scopeUtil = new Scope($storage);
        $this->assertEquals($scopeUtil->getDefaultScope('Test Default Scope Client ID'), 'clientscope1 clientscope2');
        $this->assertEquals($scopeUtil->getDefaultScope('Test Default Scope Client ID 2'), 'clientscope3');
    }
}
