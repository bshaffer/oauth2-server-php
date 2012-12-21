oauth2-server-php
=================

[![Build Status](https://secure.travis-ci.org/bshaffer/oauth2-server-php.png)](http://travis-ci.org/bshaffer/oauth2-server-php)

A library for implementing an OAuth2 Server in php

[View the Full Working Demo!](http://brentertainment.com/oauth2) ([code](https://github.com/bshaffer/oauth2-server-demo))

Autoloading
-----------

This library follows the zend [PSR-0](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-0.md) standards.  A number of
autoloaders exist which can autoload this library for that reason, but if you are not using one, you can register the `OAuth2_Autoloader`:

    require_once('/path/to/oauth2-server-php/src/OAuth2/Autoloader.php');
    OAuth2_Autoloader::register();

If you use a package library like [Composer](http://getcomposer.php), add the following to `composer.json`

    {
        "require": {
            "bshaffer/oauth2-server-php": "dev-master",
            ...
        },
        ...
    }

And then run `composer.phar install`

Get Started
-----------

Before getting started, take a look at the [Oauth2 Demo Application](http://brentertainment.com/oauth2) and the [source code](https://github.com/bshaffer/oauth2-server-demo) for a concrete example of this library in action.

The quickest way to get started is to use the following code, plugging in your database information
to the constructor of `OAuth2_Storage_Pdo`:

    $storage = new OAuth2_Storage_Pdo(array('dsn' => $dsn, 'username' => $username, 'password' => $password));
    $server = new OAuth2_Server($storage);
    $server->addGrantType(new OAuth2_GrantType_UserCredentials($storage)); // or some other grant type.  This is the simplest
    $server->handleGrantRequest(OAuth2_Request::createFromGlobals())->send();

Let's break this down line by line. The first line is how the OAuth2 data is stored.
There are several built in storage types, for your convenience.  To use PDO Storage,
instantiate the `OAuth2_Storage_Pdo` class and provide the database connection arguments:

    $storage = new OAuth2_Storage_Pdo(array('dsn' => $dsn, 'username' => $username, 'password' => $password));
    $server = new OAuth2_Server($storage);

The next step is to add a grant type.  This example uses the "User Credentials" grant type, which grants a token based on
explicit user credentials passed to the request. Read more on [supported grant types](https://github.com/bshaffer/oauth2-server-php#the-response-object)
below, or in the [OAuth2 spec](http://tools.ietf.org/html/draft-ietf-oauth-v2-20). Each grant type also requires storage,
so pass the existing storage to the constructor:

    $server->addGrantType(new OAuth2_GrantType_UserCredentials($storage));

Call the `grantAccessToken` method to validate the request for the user credentials grant type.  This will return the token
if successful.  Access the server's response object to send the successful response back, or the error response if applicable:

    $server->handleGrantRequest(OAuth2_Request::createFromGlobals())->send();

This creates the `OAuth2_Request` object from PHP global variables (most common, you can override this if need be) and sends it to the server
for assessment.  The response by default is in json format, and includes the access token if successful, and error codes if not.

Server Methods
--------------

> ...an end-user (resource owner) can grant a printing
> service (client) access to her protected photos stored at a photo
> sharing service (resource server), without sharing her username and
> password with the printing service.  Instead, she authenticates
> directly with a server trusted by the photo sharing service
> (authorization server), which issues the printing service delegation-
> specific credentials (access token).
>
>   ~ OAuth2 ([draft #31](http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-1))

Most OAuth2 APIs will have endpoints for `Authorize Requests`, `Grant Requests`, and `Access Requests`:

 * **Authorize Requests** - An endpoint requiring the user to authenticate, which redirects back to the client with an `authorization code`
 * **Grant Requests** - An endpoint which the client uses to exchange the `authorization code` for an `access token`
 * **Access Requests** - Any API method requiring oauth2 authentication.  The server will validate the incomming request, and then allow
the application to serve back the protected resource

For these tyes of requests, this library provides the following methods:

**Authorize Requests**

`handleAuthorizeRequest`
  * Receives a request object for an authorize request, returns a response object with the appropriate response

`validateAuthorizeRequest`
  * Receives a request object, returns a Boolean for whether the incoming request is a valid Authorize Request.
Applications should call this before displaying a login or authorization form to the user

**Grant Requests**

`grantAccessToken`

  * Receives a request object for a grant request, returns a token if the request is valid.

`handleGrantRequest`

  * Receives a request object for a grant request, returns a response object for the appropriate response.

`getClientCredentials`

  * parses the client credentials from the request and determines if they are valid

**Access Requests**

`verifyAccessRequest`

  * Receives a request object for an access request, finds the token if it exists, and returns a Boolean for whether
the incomming request is valid

`getAccessTokenData`

  * Takes a token string as an argument and returns the token data if applicable, or null if the token is invalid

The Response Object
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
        $parameters = $response->getParameters();

        // format as XML
        header("HTTP/1.1 " . $response->getStatusCode());
        header("Content-Type: text/xml");
        echo "<error><name>".$parameters['error']."</name><message>".$parameters['error_description']."</message></error>";
    }

This is very useful when working in a framework or existing codebase, where this library will not have full control of the response.

Grant Types
-----------

There are many supported grant types in the OAuth2 specification, and this library allows for the addition of custom grant types as well.
Supported grant types are as follows:

  1. Authorization Code

        An authorization code obtained by user authorization is exchanged for a token

  2. Implicit

        As part of user authorization, a token is retured to the client instead of an authorization code

  3. Resource Owner Password Credentials

        The username and password are submitted as part of the request, and a token is issued upon successful authentication

  4. Client Credentials

        The client can use their credentials to retrieve an access token directly, which will allow access to resources under the client's control

Create a custom grant type by implementing the `OAuth2_GrantTypeInterface` and adding it to the OAuth2 Server object.

Acknowledgements
----------------

This library is largely inspired and modified from [Quizlet's OAuth2 PHP library](https://github.com/quizlet/oauth2-php)

Contact
-------

The best way to contact me is to [file an issue](https://github.com/bshaffer/oauth2-server-php/issues/new), even for general
questions about the library, so others may find the answer.

If for whatever reason filing an issue does not make sense, contact Brent Shaffer (bshafs <at> gmail <dot> com)