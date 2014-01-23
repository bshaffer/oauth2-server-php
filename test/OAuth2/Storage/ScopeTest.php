<?php

namespace OAuth2\Storage;

use OAuth2\Scope;

class ScopeTest extends BaseTest
{
    /** @dataProvider provideStorage */
    public function testScopeExists($storage = null)
    {
        if ($storage instanceof NullStorage) {
            $this->markTestSkipped('Skipped Storage: ' . $storage);

            return;
        }

        if (!$storage instanceof ScopeInterface) {
            // incompatible storage
            return;
        }

        //Test getting scopes
        $scopeUtil = new Scope($storage);
        $this->assertTrue($scopeUtil->scopeExists('supportedscope1'));
        $this->assertTrue($scopeUtil->scopeExists('supportedscope1 supportedscope2 supportedscope3'));
        $this->assertFalse($scopeUtil->scopeExists('fakescope'));
        $this->assertFalse($scopeUtil->scopeExists('supportedscope1 supportedscope2 supportedscope3 fakescope'));
    }

    /** @dataProvider provideStorage */
    public function testGetDefaultScope($storage = null)
    {
        if ($storage instanceof NullStorage) {
            $this->markTestSkipped('Skipped Storage: ' . $storage);

            return;
        }

        if (!$storage instanceof ScopeInterface) {
            // incompatible storage
            return;
        }

        // test getting default scope
        $scopeUtil = new Scope($storage);
        $this->assertEquals($scopeUtil->getDefaultScope(), 'defaultscope1 defaultscope2');
        $this->assertEquals($scopeUtil->getDefaultScope("Test Client ID With Default Scope"), 'clientdefaultscope1 clientdefaultscope2');
    }
}
