<?php

/**
*
*/
class OAuth2_Response implements OAuth2_ResponseInterface
{
    protected $statusCode = 200;
    protected $responseParameters = array();
    protected $httpHeaders = array();

    public function setStatusCode($statusCode)
    {
        $this->statusCode = $statusCode;
    }

    public function getStatusCode()
    {
        return $this->statusCode;
    }

    public function setResponseParameters($responseParameters)
    {
        $this->responseParameters = $responseParameters;
    }

    public function getResponseParameters()
    {
        return $responseParameters;
    }

    public function setHttpHeaders($httpHeaders)
    {
        $this->httpHeaders = $httpHeaders;
    }

    public function getHttpHeaders()
    {
        return $this->httpHeaders;
    }

    public function setErrorResponse($statusCode, $error, $errorDescription)
    {
        $this->setStatusCode($statusCode);
        $this->setResponseParameters(array(
            'error' => $error,
            'error_description' => $errorDescription,
        ));
        $this->setHttpHeaders(array(
            "Content-Type: application/json",
            "Cache-Control: no-store",
        ));
    }

    public function getResponseBody()
    {
        return json_encode($this->responseParameters, true);
    }

    public function send()
    {
        header("HTTP/1.1 " . $this->getStatusCode());
        foreach ($this->getHttpHeaders() as $header) {
            header($header);
        }
        echo $this->getResponseBody();
    }
}