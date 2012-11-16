<?php

interface OAuth2_GrantTypeInterface
{
    public function getQuerystringIdentifier();
    public function validateRequest($request);
    public function getTokenDataFromRequest($request);
    public function validateTokenData($tokenData, array $clientData);
    public function finishGrantRequest($token);
}