<?php

class OAuth2_ResponseTest extends PHPUnit_Framework_TestCase
{
    public function testRenderAsXml()
    {
        $response = new OAuth2_Response(array(
            'foo' => 'bar',
            'halland' => 'oates',
        ));

        $string = $response->getResponseBody('xml');
        $this->assertContains('<response><bar>foo</bar><oates>halland</oates></response>', $string);
    }
    public function testRenderAsXmlHeaders()
    {
        $response = new OAuth2_Response(array(
            'foo' => 'bar',
            'halland' => 'oates',
        ));

        $headers = $response->getHttpHeaders('xml');
        $this->assertEquals(array('Content-Type' => 'text/xml'), $headers);
    }
    public function testRenderAsJsonHeaders()
    {
        $response = new OAuth2_Response(array(
            'foo' => 'bar',
            'halland' => 'oates',
        ));

        $headers = $response->getHttpHeaders();
        $this->assertEquals(array('Content-Type' => 'application/json'), $headers);
    }
}
