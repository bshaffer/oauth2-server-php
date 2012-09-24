oauth2-server-php
=================

A library for implementing an OAuth2 Server in php

Largely inspired and modified from [Quizlet's OAuth2 PHP library](https://github.com/quizlet/oauth2-php)

THIS PROJECT IS STILL UNDER DEVELOPMENT

Get Started
-----------

The quickest way to get started is to use the following code, plugging in your database information
to the constructor of OAuth2_Storage_Pdo:

    $storage = new OAuth2_Storage_Pdo($dsn, $username, $password);
    $server = new OAuth2_Server($storage);
    $server->addGrantType(new OAuth2_GrantType_UserCredentials($storage); // or some other grant type.  This is the easiest
    $server->grantAccessToken();
    $server->getResponse()->send();

Let's break this down line by line. The first line is how the OAuth2 data is stored.
There are several built in storage types, for your convenience.  To use the PDO Storage,
instantiate the OAuth2_Storage_Pdo class and provide the database connection arguments:

    $storage = new OAuth2_Storage_Pdo($dsn, $username, $password);
    $server = new OAuth2_Server($storage);

The next step is to add a grant type.  There are many supported grant types in the OAuth2 specification,
and this library allows for the addition of custom grant types as well. This example uses the "User Credentials" grant type,
which grants a token based on explicit user credentials passed to the request. Read more on supported grant types below, or
in the OAuth2 spec.  Each grant type also requires storage, so pass the existing storage to the constructor:

    $server->addGrantType(new OAuth2_GrantType_UserCredentials($storage));

Call the `grantAccessToken` method to validate the request for the user credentials grant type.  This will return the token
if successful.  Access the server's response object to send the successful response back, or the error response if applicable:

    $token = $server->grantAccessToken();
    $server->getResponse()->send();

The Resposne Object
-------------------

The response object serves the purpose of making your server OAuth2 compliant.  It will set the appropriate status codes, headers,
and response body for a valid or invalid oauth request.  To use it as it's simplest level, just send the output and exit:

    // will set headers, status code, and json response appropriately for success or failure
    $server->grantAccessToken();
    $server->getResponse()->send();

The response object can also be used to customize output. Below, if the request is NOT valid, the error is sent to the browser:

    if (!$token = $server->grantAccessToken()) {
        $server->getResponse()->send();
        die();
    }
    echo sprintf('Your token is %s!!', $token);

This will populate the appropriate error headers, and return a json error response.  If you do not want to send a JSON response,
the response object can be used to display the information in any other format:

    if (!$token = $server->grantAccessToken()) {
        $response = $server->getResponse();
        $parameters = $response->getResponseParameters();

        // format as HTML
        header("HTTP/1.1 " . $response->getStatusCode());
        header("Content-Type: text/xml");
        echo "<error><name>".$parameters['error']."</name><message>".$parameters['error_description']."</message></error>";
    }

This is very useful when working in a framework or existing codebase, where this library will not have full control of the response.

Contact
-------

Please contact Brent Shaffer (bshafs <at> gmail <dot> com) for more information