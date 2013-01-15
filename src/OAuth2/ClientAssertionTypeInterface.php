<?php

interface OAuth2_ClientAssertionTypeInterface
{
	public function validateClientCredentials($tokenData);
}