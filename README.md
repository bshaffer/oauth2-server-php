oauth2-server-php
=================

[![Build Status](https://secure.travis-ci.org/bshaffer/oauth2-server-php.png)](http://travis-ci.org/bshaffer/oauth2-server-php)

An OAuth2.0 Server in PHP!

[View the Full Working Demo!](http://brentertainment.com/oauth2) ([code](https://github.com/bshaffer/oauth2-server-demo))

Installation
------------

This library follows the zend [PSR-0](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-0.md) standards.  A number of
autoloaders exist which can autoload this library for that reason, but if you are not using one, you can register the `OAuth2_Autoloader`:

```php
require_once('/path/to/oauth2-server-php/src/OAuth2/Autoloader.php');
OAuth2_Autoloader::register();
```

Using [Composer](http://getcomposer.php)? Add the following to `composer.json`:

```
{
    "require": {
        "bshaffer/oauth2-server-php": "v0.7",
        ...
    },
    ...
}
```

And then run `composer.phar install`

> Checkout out the tag `v0.7` will ensure your application doesn't break from backwards-compatibility issues, but also this means you
> will not receive the latest changes.  To ride the bleeding edge of development, use `dev-develop` instead.

Learning OAuth2.0
-----------------

If you are new to OAuth2, take a little time first to look at the [Oauth2 Demo Application](http://brentertainment.com/oauth2) and the [source code](https://github.com/bshaffer/oauth2-server-demo).  This will help you with understanding the basic OAuth2 flows.

Get Started
-----------

The quickest way to get started is to use the following schema to create the default database:

```sql
CREATE TABLE oauth_clients (client_id TEXT, client_secret TEXT, redirect_uri TEXT);
CREATE TABLE oauth_access_tokens (access_token TEXT, client_id TEXT, user_id TEXT, expires TIMESTAMP, scope TEXT);
CREATE TABLE oauth_authorization_codes (authorization_code TEXT, client_id TEXT, user_id TEXT, redirect_uri TEXT, expires TIMESTAMP, scope TEXT);
CREATE TABLE oauth_refresh_tokens (refresh_token TEXT, client_id TEXT, user_id TEXT, expires TIMESTAMP, scope TEXT);
```

Once you have done this, use your database information to create an instance of `OAuth2_Storage_Pdo`:

```php
/*
 * OAuth 2.0 Token Controller
 *
 * Save this to "token.php", or make available at /token
 */

// Autoloading (composer is preferred, but for this example let's just do this)
require_once('path/to/oauth2-server-php/src/OAuth2/Autoloader.php');
OAuth2_Autoloader::register();

// $dsn is the Data Source Name for your database, for exmaple "mysql:dbname=my_oauth2_db;host=localhost"
$storage = new OAuth2_Storage_Pdo(array('dsn' => $dsn, 'username' => $username, 'password' => $password));

// Pass a storage object or array of storage objects to the OAuth2 server class
$server = new OAuth2_Server($storage);

// Add the OAuth2.0 Grant Types
$server->addGrantType(new OAuth2_GrantType_ClientCredentials($storage)); // or some other grant type.  This is the simplest

// Handle a request for an OAuth2.0 Access Token and send the response to the client
$server->handleTokenRequest(OAuth2_Request::createFromGlobals(), $response = new OAuth2_Response());
$response->send();
```

Congratulatons!  You have created a **Token Controller**!  Do you want to see it in action? Run the following SQL:

```sql
INSERT INTO oauth_clients (client_id, client_secret, redirect_uri) VALUES ("testclient", "testpass", NULL);
```

Now run the following from the command line:

```bash
curl -u testclient:testpass http://localhost/token.php -d 'grant_type=client_credentials'
```

> Note: http://localhost/token.php assumes you have the file `token.php` on your local machine, and you have
> set up the "localhost" webhost to point to it.  This will vary per your configuration.

If everything works, you should receive a response like this:

```json
{"access_token":"03807cb390319329bdf6c777d4dfae9c0d3b3c35","expires_in":3600,"token_type":"bearer","scope":null}
```

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
>   ~ OAuth2 ([draft #31](http://tools.ietf.org/html/rfc6749#section-1))

Most OAuth2 APIs will have endpoints for `Authorize Requests`, `Token Requests`, and `Resource Requests`.  The `OAuth2_Server` object has methods to handle each of these requests.

### Authorize Requests

An endpoint requiring the user to authenticate, which redirects back to the client with an `authorization code`.

**methods**:

`handleAuthorizeRequest`
  * Receives a request object for an authorize request, returns a response object with the appropriate response

`validateAuthorizeRequest`
  * Receives a request object, returns false if the incoming request is not a valid Authorize Request. If the request
is valid, returns an array of retrieved client details together with input.
Applications should call this before displaying a login or authorization form to the user

### Token Requests

An endpoint which the client uses to exchange the `authorization code` for an `access token`.

**methods**:

`grantAccessToken`

  * Receives a request object for a token request, returns a token if the request is valid.

`handleTokenRequest`

  * Receives a request object for a token request, returns a response object for the appropriate response.

### Resource Requests

Any API method requiring oauth2 authentication.  The server will validate the incomming request, and then allow
the application to serve back the protected resource.

**methods**:

`verifyResourceRequest`

  * Receives a request object for a resource request, finds the token if it exists, and returns a Boolean for whether
the incomming request is valid

`getAccessTokenData`

  * Takes a token string as an argument and returns the token data if applicable, or null if the token is invalid

Grant Types
-----------

There are many supported grant types in the OAuth2 specification, and this library allows for the addition of custom grant types as well.
Supported grant types are as follows:

  1. [Authorization Code](http://tools.ietf.org/html/rfc6749#section-4.1)

        An authorization code obtained by user authorization is exchanged for a token

  2. [Implicit](http://tools.ietf.org/html/rfc6749#section-4.2)

        As part of user authorization, a token is retured to the client instead of an authorization code

  3. [Resource Owner Password Credentials](http://tools.ietf.org/html/rfc6749#section-4.3)

        The username and password are submitted as part of the request, and a token is issued upon successful authentication

  4. [Client Credentials](http://tools.ietf.org/html/rfc6749#section-4.4)

        The client can use their credentials to retrieve an access token directly, which will allow access to resources under the client's control

  5. [JWT Authorization Grant](http://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-04#section-4)

        The client can submit a JWT (JSON Web Token) in a request to the token endpoint. An access token (without a refresh token) is then returned directly.

  6. [Refresh Token](http://tools.ietf.org/html/rfc6749#section-6)

        The client can submit refresh token and recieve a new access token e.g. it may be necessary to do this if the access_token had expired.

When submitting a request for an access_token using either the 'Authorization Code' or 'Resource Owner Password
Credential' grant, a refresh_token is provided. However, When using the refresh_token from above to request a new
access_token, a new refresh_token is not provided. The spec does not strictly require a refresh_token be granted but it
is [still possible to do it](http://tools.ietf.org/html/rfc6749#section-6).

As a result, the option always_issue_new_refresh_token was added (defaults to FALSE) in the
[OAuth2_GrantType_RefreshToken](src/OAuth2/GrantType/RefreshToken.php) class. So, by default a new refresh token is not
issued, but you can easily configure this to do so by setting `'always_issue_new_refresh_token' => true`

If you want to support more than one grant type it is possible to add more than 1 type to the $server as you
initialize, see below.

```php
$server->addGrantType(new OAuth2_GrantType_UserCredentials($storage));
$server->addGrantType(new OAuth2_GrantType_RefreshToken($storage));
$server->addGrantType(new OAuth2_GrantType_AuthorizationCode($storage));
```

Create a custom grant type by implementing the `OAuth2_GrantTypeInterface` and adding it to the OAuth2 Server object.

The Response Object
-------------------

The response object serves the purpose of making your server OAuth2 compliant.  It will set the appropriate status codes, headers,
and response body for a valid or invalid oauth request.  To use it as it's simplest level, just send the output and exit:

```php
$request = OAuth2_Request::createFromGlobals();
$response = new OAuth2_Response();

// will set headers, status code, and json response appropriately for success or failure
$server->grantAccessToken($request, $response);
$response->send();
```

The response object can also be used to customize output. Below, if the request is NOT valid, the error is sent to the browser:

```php
if (!$token = $server->grantAccessToken($request, $response)) {
    $response->send();
    die();
}
echo sprintf('Your token is %s!!', $token);
```

This will populate the appropriate error headers, and return a json error response.  If you do not want to send a JSON response,
the response object can be used to display the information in any other format:

```php
if (!$token = $server->grantAccessToken($request, $response)) {
    $parameters = $response->getParameters();
    // format as XML
    header("HTTP/1.1 " . $response->getStatusCode());
    header("Content-Type: text/xml");
    echo "<error><name>".$parameters['error']."</name><message>".$parameters['error_description']."</message></error>";
}
```

This is very useful when working in a framework or existing codebase, where this library will not have full control of the response.

Scope
-----

####Configure your Scope

The use of Scope in an OAuth2 application is often key to proper permissioning. Scope is used to limit the authorization
granted to the client by the resource owner. The most popular use of this is Facebook's ability for users to authorize
a variety of different functions to the client ("access basic information", "post on wall", etc).

In this library, scope is handled by implementing `OAuth2_Storage_ScopeInterface`. This can be done using your own
implementation, or by taking advantage of the existing `OAuth2_Storage_Memory` class:

```php
// configure your available scopes
$defaultScope = 'basic';
$supportedScopes = array(
  'basic',
  'postonwall',
  'accessphonenumber'
);
$memory = new OAuth2_Storage_Memory(array(
  'default_scope' => $defaultScope,
  'supported_scopes' => $supportedScopes
));
$scopeUtil = new OAuth2_Scope($memory);

$server->setScopeUtil($scopeUtil);
```

This is the simplest way, but scope can by dynamically configured as well:

```php
// configure your available scopes
$doctrine = Doctrine_Core::getTable('OAuth2Scope');
$scopeUtil = new OAuth2_Scope($doctrine);

$server->setScopeUtil($scopeUtil);
```

This example assumes the class being used implements `OAuth2_Storage_ScopeInterface`:

```php
class OAuth2ScopeTable extends Doctrine_Table implements OAuth2_Storage_ScopeInterface
{
    public function getDefaultScope()
    {
        //...
    }

    public function scopeExists($scope, $client_id = null)
    {
        //...
    }
}
```

####Validate your scope

Configuring your scope in the server class will ensure requested scopes by the client are valid.  However, there are two
steps required to ensure the proper validation of your scope.  First, the requested scope must be exposed to the resource
owner upon authorization.  In this library, this is left 100% to the implementation.  The UI or whathaveyou must make clear
the scope of the authorization being granted.  Second, the resource request itself must specify what scope is required to
access it:

```php
// https://api.example.com/resource-requiring-postonwall-scope
$request = OAuth2_Request::createFromGlobals();
$response = new OAuth2_Response();
$scopeRequired = 'postonwall'; // this resource requires "postonwall" scope
if (!$server->verifyResourceRequest($request, $response, $scopeRequired)) {
  // if the scope required is different from what the token allows, this will send a "401 insufficient_scope" error
  $response->send();
}
```

####Customizing your scope

As the implementation of "scope" can be significantly different for each application, providing a different class other than
OAuth2_Scope can be beneficial.  Implement `OAuth2_ScopeInterface` in a custom class to fully customize.

Acknowledgements
----------------

This library is largely inspired and modified from [Quizlet's OAuth2 PHP library](https://github.com/quizlet/oauth2-php)

Contact
-------

The best way to get help and ask questions is to [file an issue](https://github.com/bshaffer/oauth2-server-php/issues/new).  This will
help answer questions for others as well.

If for whatever reason filing an issue does not make sense, contact Brent Shaffer (bshafs <at> gmail <dot> com)
