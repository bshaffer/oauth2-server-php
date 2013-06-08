<?php

class OAuth2_TokenType_BearerTest extends PHPUnit_Framework_TestCase
{
    public function testValidContentTypeWithCharset()
    {
        $bearer = new OAuth2_TokenType_Bearer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'access_token' => 'ThisIsMyAccessToken'
        ));
        $request->server['CONTENT_TYPE'] = 'application/x-www-form-urlencoded; charset=UTF-8';

        $param = $bearer->getAccessTokenParameter($request, $response = new OAuth2_Response());
        $this->assertEquals($param, 'ThisIsMyAccessToken');
    }

    public function testInvalidContentType()
    {
        $bearer = new OAuth2_TokenType_Bearer();
        $request = OAuth2_Request_TestRequest::createPost(array(
            'access_token' => 'ThisIsMyAccessToken'
        ));
        $request->server['CONTENT_TYPE'] = 'application/json; charset=UTF-8';

        $param = $bearer->getAccessTokenParameter($request, $response = new OAuth2_Response());
        $this->assertNull($param);
        $this->assertEquals($response->getStatusCode(), 400);
        $this->assertEquals($response->getParameter('error'), 'invalid_request');
        $this->assertEquals($response->getParameter('error_description'), 'The content type for POST requests must be "application/x-www-form-urlencoded"');
    }
}
