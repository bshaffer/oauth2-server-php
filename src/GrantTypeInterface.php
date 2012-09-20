<?php

interface OAuth2_GrantTypeInterface
{
    public function validateInputParameters(array $parameters);
    public function getTokenDataFromInputParameters(array $parameters);
    public function validateTokenData(array $tokenData);
}