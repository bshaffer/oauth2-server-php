<?php

class OAuth2_ScopeTest extends PHPUnit_Framework_TestCase
{
    public function testCheckScope()
    {
        $scopeUtil = new OAuth2_Scope();

        $this->assertFalse($scopeUtil->checkScope('invalid', 'list of scopes'));
        $this->assertFalse($scopeUtil->checkScope('invalid', array('list', 'of', 'scopes')));

        $this->assertTrue($scopeUtil->checkScope('valid', 'valid and-some other-scopes'));
        $this->assertTrue($scopeUtil->checkScope('valid', array('valid', 'and-some', 'other-scopes')));

        $this->assertTrue($scopeUtil->checkScope('valid another-valid', 'valid another-valid and-some other-scopes'));
        $this->assertTrue($scopeUtil->checkScope('valid another-valid', array('valid', 'another-valid', 'and-some', 'other-scopes')));

        // all scopes must match
        $this->assertFalse($scopeUtil->checkScope('valid invalid', 'valid and-some other-scopes'));
        $this->assertFalse($scopeUtil->checkScope('valid invalid', array('valid', 'and-some', 'other-scopes')));
        $this->assertFalse($scopeUtil->checkScope('valid valid2 invalid', 'valid valid2 and-some other-scopes'));
        $this->assertFalse($scopeUtil->checkScope('valid valid2 invalid', array('valid', 'valid2', 'and-some', 'other-scopes')));
    }

    public function testScopeStorage()
    {
        $scopeUtil = new OAuth2_Scope();

        $this->assertEquals($scopeUtil->getDefaultScope(), null);
        $this->assertEquals($scopeUtil->getSupportedScopes('client_id'), array());

        $scopeUtil = new OAuth2_Scope(array(
            'default_scope' => 'default',
            'supported_scopes' => array('this', 'that', 'another'),
        ));

        $this->assertEquals($scopeUtil->getDefaultScope(), 'default');
        $this->assertEquals($scopeUtil->getSupportedScopes('client_id'), array('this', 'that', 'another'));

        $memoryStorage = new OAuth2_Storage_Memory(array(
            'default_scope' => 'base',
            'supported_scopes' => 'only-this-one',
        ));
        $scopeUtil = new OAuth2_Scope($memoryStorage);

        $this->assertEquals($scopeUtil->getDefaultScope(), 'base');
        $this->assertEquals($scopeUtil->getSupportedScopes('client_id'), 'only-this-one');
    }
}
