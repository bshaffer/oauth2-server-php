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
}