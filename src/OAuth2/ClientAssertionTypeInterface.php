<?php

interface OAuth2_ClientAssertionTypeInterface
{
    public function getClientDataFromRequest(OAuth2_RequestInterface $request);

    public function validateClientData(array $clientData, $grantTypeIdentifier);
}
