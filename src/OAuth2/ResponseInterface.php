<?php

interface OAuth2_ResponseInterface
{
    public function setStatusCode($statusCode);
    public function setResponseParameters($repsonseParameters);
    public function setHttpHeaders($httpHeaders);
    public function setErrorResponse($statusCode, $error, $errorDescription);
}