<?php

interface OAuth2_GrantTypeInterface
{
    public function validateRequest($request);
    public function getTokenDataFromRequest($request);
    public function validateTokenData(array $tokenData, array $clientData);
    public function getIdentifier();
    public function finishTokenGrant($token);
}