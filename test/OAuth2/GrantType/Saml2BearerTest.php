<?php

namespace OAuth2\GrantType;

use OAuth2\Storage\Bootstrap;
use OAuth2\Server;
use OAuth2\Request\TestRequest;
use OAuth2\Response;

/**
 * There is not much to test in here really. Most of the saml2 logic its handled inside the
 * SamlAssertion helper that the class uses.
 */
class Saml2BearerTest extends \PHPUnit_Framework_TestCase
{
    public function testNoClientIDRequest()
    {
        //draft allows no client_id, but we do not right now
        $assertion = $this->getSamlAssertionMock();
        $server = $this->getTestServer($assertion);

        $request = TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:saml2-bearer', // valid grant type
            'assertion' => 'some assertion',
            'no_client_id' => 'client',
        ));

        $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('invalid_client', $response->getParameter('error'));
        $this->assertEquals('Client credentials were not found in the headers or body', $response->getParameter('error_description'));
    }

    public function testNoAssertionRequest()
    {
        $assertion = $this->getSamlAssertionMock();
        $server = $this->getTestServer($assertion);

        $request = TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:saml2-bearer', // valid grant type
            'not_an_assertion' => 'any as its not tested',
            'client_id'     => 'Client ID With User ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
        ));

        $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals('Missing parameters: "assertion" required', $response->getParameter('error_description'));
    }

    public function testAssertionIsValidated()
    {
        $assertion = $this->getSamlAssertionMock();
        $server = $this->getTestServer($assertion);

        $request = TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:saml2-bearer', // valid grant type
            'assertion' => 'any as its not tested',
            'client_id'     => 'Client ID With User ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
        ));

        $assertion->expects($this->once())
            ->method('setRawAssertion')
            ->with('any as its not tested');

        $assertion->expects($this->once())
            ->method('validate')
            ->willReturn(null);

        $token = $server->grantAccessToken($request, $response = new Response());

        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
    }

    public function testAssertionValidationError()
    {
        $assertion = $this->getSamlAssertionMock();
        $server = $this->getTestServer($assertion);

        $request = TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:saml2-bearer', // valid grant type
            'assertion' => 'any as its not tested',
            'client_id'     => 'Client ID With User ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
        ));

        $assertion->expects($this->once())
            ->method('validate')
            ->willReturn(array('error' => 'some validation error'));

        $token = $server->grantAccessToken($request, $response = new Response());

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('invalid_grant', $response->getParameter('error'));
        $this->assertEquals('some validation error', $response->getParameter('error_description'));
    }

    public function testValidSamlWithScope()
    {
        $assertion = $this->getSamlAssertionMock();
        $server = $this->getTestServer($assertion);

        $request = TestRequest::createPost(array(
            'grant_type' => 'urn:ietf:params:oauth:grant-type:saml2-bearer', // valid grant type
            'assertion' => 'any as its not tested',
            'client_id'     => 'Client ID With User ID', // valid client id
            'client_secret' => 'TestSecret', // valid client secret
            'scope' => 'scope1',
        ));

        $token = $server->grantAccessToken($request, new Response());

        $this->assertNotNull($token);
        $this->assertArrayHasKey('access_token', $token);
        $this->assertArrayHasKey('scope', $token);
        $this->assertEquals('scope1', $token['scope']);
    }

    private function getTestServer($samlAssertionInterface)
    {
        $storage = Bootstrap::getInstance()->getMemoryStorage();
        $server = new Server($storage);
        $settings = 'not_tested_here';
        $server->addGrantType(new Saml2Bearer($settings, $samlAssertionInterface));

        $server->addGrantType(new ClientCredentials($storage));

        return $server;
    }

    private function getSamlAssertionMock()
    {
        return $this->getMockBuilder('OAuth2\Saml\Saml2AssertionInterface')
            ->getMock();
    }
}
