oauth2-server-php
=================

[![Build Status](https://secure.travis-ci.org/bshaffer/oauth2-server-php.png)](http://travis-ci.org/bshaffer/oauth2-server-php)

An OAuth2.0 Server in PHP! [View the Full Working Demo](http://brentertainment.com/oauth2) ([code](https://github.com/bshaffer/oauth2-demo-php))

Requirements
------------

PHP 5.3.9+ is required, but there is a [stable release](https://github.com/bshaffer/oauth2-server-php/tree/v0.9) and [developement branch](https://github.com/bshaffer/oauth2-server-php/tree/php5.2-develop) for PHP 5.2.0 to 5.3.8.

Installation
------------

This library follows the zend [PSR-0](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-0.md) standards.  A number of
autoloaders exist which can autoload this library for that reason, but if you are not using one, you can register the `OAuth2\Autoloader`:

```php
require_once('/path/to/oauth2-server-php/src/OAuth2/Autoloader.php');
OAuth2\Autoloader::register();
```

Using [Composer](http://getcomposer.php)? Add the following to `composer.json`:

```
{
    "require": {
        "bshaffer/oauth2-server-php": "dev-develop",
        ...
    },
    ...
}
```

And then run `composer.phar install`

> It is highly recommended you check out the [`v0.9`](https://github.com/bshaffer/oauth2-server-php/tree/v0.9) tag to
> ensure your application doesn't break from backwards-compatibility issues, but also this means you
> will not receive the latest changes.

Learning OAuth2.0
-----------------

If you are new to OAuth2, take a little time first to look at the [Oauth2 Demo Application](http://brentertainment.com/oauth2) and the [source code](https://github.com/bshaffer/oauth2-demo-php), and read up on [OAuth2 Flows](http://drupal.org/node/1958718).  For everything else, consult the [OAuth2.0 Specification](http://tools.ietf.org/html/rfc6749)

Get Started
-----------

Here is an example of a bare-bones OAuth2 Server implementation:

```php
$storage = new OAuth2\Storage\Pdo(array('dsn' => $dsn, 'username' => $username, 'password' => $password));
$server = new OAuth2\Server($storage);
$server->addGrantType(new OAuth2\GrantType\AuthorizationCode($storage)); // or any grant type you like!
$server->handleTokenRequest(OAuth2\Request::createFromGlobals())->send();
```

This library requires you to define a `Storage` object, containing instrutions on how to interact with objects in your storage
layer such as [OAuth Clients](https://github.com/bshaffer/oauth2-server-php/blob/develop/src/OAuth2/Storage/ClientInterface.php) and
[Authorization Codes](https://github.com/bshaffer/oauth2-server-php/blob/develop/src/OAuth2/Storage/AuthorizationCodeInterface.php).
Built-in storage classes include [PDO](https://github.com/bshaffer/oauth2-server-php/blob/develop/src/OAuth2/Storage/Pdo.php),
[Redis](https://github.com/bshaffer/oauth2-server-php/blob/develop/src/OAuth2/Storage/Redis.php), and
[Mongo](https://github.com/bshaffer/oauth2-server-php/blob/develop/src/OAuth2/Storage/Mongo.php).  The interfaces allow (and encourage)
the use of your own Storage objects to fit your application's implementation.

Once you've created a storage object, pass it to the server object and define which Grant Types your server is to support.  See
the list of supported [Grant Types](#grant-types) below.

The final step, once the Server object is set up, is to handle the incoming request.  Consult the [Server Methods](#server-methods), or
follow the [Step-by-Step Walkthrough](#step-by-step-walkthrough) to familiarize yourself with the types of requests involved in
OAuth2.0 workflows.

Step-by-Step Walkthrough
------------------------

The following instructions provide a detailed walkthrough to help you get an OAuth2 server
up and running.  To see the codebase of an existing OAuth2 server implementing this library,
check out the [OAuth2 Demo](https://github.com/bshaffer/oauth2-demo-php).

### Initialize your Project

Create a directory for your project and pull in this library

```bash
mkdir my-oauth2-walkthrough
cd my-oauth2-walkthrough
git clone https://github.com/bshaffer/oauth2-server-php.git
```

### Define your Schema

Now use the following schema to create the default database:

##### MySQL / SQLite / PostgreSQL / MS SQL Server
```sql
CREATE TABLE oauth_clients (client_id VARCHAR(80) NOT NULL, client_secret VARCHAR(80) NOT NULL, redirect_uri VARCHAR(2000) NOT NULL, CONSTRAINT client_id_pk PRIMARY KEY (client_id));
CREATE TABLE oauth_access_tokens (access_token VARCHAR(40) NOT NULL, client_id VARCHAR(80) NOT NULL, user_id VARCHAR(255), expires TIMESTAMP NOT NULL, scope VARCHAR(2000), CONSTRAINT access_token_pk PRIMARY KEY (access_token));
CREATE TABLE oauth_authorization_codes (authorization_code VARCHAR(40) NOT NULL, client_id VARCHAR(80) NOT NULL, user_id VARCHAR(255), redirect_uri VARCHAR(2000), expires TIMESTAMP NOT NULL, scope VARCHAR(2000), CONSTRAINT auth_code_pk PRIMARY KEY (authorization_code));
CREATE TABLE oauth_refresh_tokens (refresh_token VARCHAR(40) NOT NULL, client_id VARCHAR(80) NOT NULL, user_id VARCHAR(255), expires TIMESTAMP NOT NULL, scope VARCHAR(2000), CONSTRAINT refresh_token_pk PRIMARY KEY (refresh_token));
CREATE TABLE oauth_users (username VARCHAR(255) NOT NULL, password VARCHAR(2000), first_name VARCHAR(255), last_name VARCHAR(255), CONSTRAINT username_pk PRIMARY KEY (username));
```

### Bootstrap your OAuth2 Server

We need to create and configure our OAuth2 Server object.  This will be used
by all the endpoints in our application.  Name this file `server.php`:

```php
$dsn      = 'mysql:dbname=my_oauth2_db;host=localhost';
$username = 'root';
$password = '';

// error reporting (this is a demo, after all!)
ini_set('display_errors',1);error_reporting(E_ALL);

// Autoloading (composer is preferred, but for this example let's just do this)
require_once('oauth2-server-php/src/OAuth2/Autoloader.php');
OAuth2\Autoloader::register();

// $dsn is the Data Source Name for your database, for exmaple "mysql:dbname=my_oauth2_db;host=localhost"
$storage = new OAuth2\Storage\Pdo(array('dsn' => $dsn, 'username' => $username, 'password' => $password));

// Pass a storage object or array of storage objects to the OAuth2 server class
$server = new OAuth2\Server($storage);

// Add the "Client Credentials" grant type (it is the simplest of the grant types)
$server->addGrantType(new OAuth2\GrantType\ClientCredentials($storage));

// Add the "Authorization Code" grant type (this is where the oauth magic happens)
$server->addGrantType(new OAuth2\GrantType\AuthorizationCode($storage));
```

> Note: Be sure to define the `$dsn`, `$username`, and `$password` variables to be the
> appropriate values for your database.

### Create a Token Controller

Next, we will create the **Token Controller**. This is the URI which returns an OAuth2.0 Token to the client.
Here is an example of a token controller in the file `token.php`:

```php
// include our OAuth2 Server object
require_once __DIR__.'/server.php';

// Handle a request for an OAuth2.0 Access Token and send the response to the client
$server->handleTokenRequest(OAuth2\Request::createFromGlobals())->send();
```

Congratulatons!  You have created a **Token Controller**!  Do you want to see it in action? Run the following SQL to
create an OAuth Client:

```sql
INSERT INTO oauth_clients (client_id, client_secret, redirect_uri) VALUES ("testclient", "testpass", "http://fake/");
```

Now run the following from the command line:

```bash
curl -u testclient:testpass http://localhost/token.php -d 'grant_type=client_credentials'
```

> Note: http://localhost/token.php assumes you have the file `token.php` on your local machine, and you have
> set up the "localhost" webhost to point to it.  This may vary for your application.

If everything works, you should receive a response like this:

```json
{"access_token":"03807cb390319329bdf6c777d4dfae9c0d3b3c35","expires_in":3600,"token_type":"bearer","scope":null}
```

### Create a Resource Controller

Now that you are creating tokens, you'll want to validate them in your APIs.  Here is an
example of a resource controller in the file `resource.php`:

```php
// include our OAuth2 Server object
require_once __DIR__.'/server.php';

// Handle a request for an OAuth2.0 Access Token and send the response to the client
if (!$server->verifyResourceRequest(OAuth2\Request::createFromGlobals())) {
    $server->getResponse()->send();
    die;
}
echo json_encode(array('success' => true, 'message' => 'You accessed my APIs!'));
```

Now run the following from the command line:

```bash
curl http://localhost/resource.php -d 'access_token=YOUR_TOKEN'
```

> Note: Use the value returned in "access_token" from the previous step in place of YOUR_TOKEN

If all goes well, you should receive a response like this:

```json
{"success":true,"message":"You accessed my APIs!"}
```

### Create an Authorize Controller

Authorize Controllers are the "killer feature" of OAuth2, and allow for your users to authorize
third party applications.  Instead of issuing an Access Token straightaway as happened in
the first token controller example, in this example an authorize controller is used to only issue
a token once the user has authorized the request. Create `authorize.php`:

```php
// include our OAuth2 Server object
require_once __DIR__.'/server.php';

$request = OAuth2\Request::createFromGlobals();
$response = new OAuth2\Response();

// validate the authorize request
if (!$server->validateAuthorizeRequest($request, $response)) {
    $response->send();
    die;
}
// display an authorization form
if (empty($_POST)) {
  exit('
<form method="post">
  <label>Do You Authorize TestClient?</label><br />
  <input type="submit" name="authorized" value="yes">
  <input type="submit" name="authorized" value="no">
</form>');
}

// print the authorization code if the user has authorized your client
$is_authorized = ($_POST['authorized'] === 'yes');
$server->handleAuthorizeRequest($request, $response, $is_authorized);
if ($is_authorized) {
  // this is only here so that you get to see your code in the cURL request. Otherwise, we'd redirect back to the client
  $code = substr($response->getHttpHeader('Location'), strpos($response->getHttpHeader('Location'), 'code=')+5, 40);
  exit("SUCCESS! Authorization Code: $code");
}
$response->send();
```

Now paste the following URL in your browser

```
http://localhost/authorize.php?response_type=code&client_id=testclient&state=xyz
```

You will be prompted with an authorization form, and receive an authorization code upon clicking "yes"

The Authorization Code can now be used to receive an access token from your previously
created `token.php` endpoint.  Just call this endpoint using the returned authorization code:
```bash
curl -u testclient:testpass http://localhost/token.php -d 'grant_type=authorization_code&code=YOUR_CODE'
```

And just as before, you will receive an access token:

```json
{"access_token":"6f05ad622a3d32a5a81aee5d73a5826adb8cbf63","expires_in":3600,"token_type":"bearer","scope":null}
```

> Note: Be sure to do this quickly, because Authorization Codes expire in 30 seconds!

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

  7. [Extension Grant](http://tools.ietf.org/html/rfc6749#section-4.5)

        Create your own grant type by implementing the `OAuth2\GrantType\GrantTypeInterface` and adding it to the OAuth2 Server object.

When submitting a request for an access_token using either the 'Authorization Code' or 'Resource Owner Password
Credential' grant, a refresh_token is provided. However, When using the refresh_token from above to request a new
access_token, a new refresh_token is not provided. The spec does not strictly require a refresh_token be granted but it
is [still possible to do it](http://tools.ietf.org/html/rfc6749#section-6).

As a result, the option always_issue_new_refresh_token was added (defaults to FALSE) in the
[OAuth2\GrantType\RefreshToken](src/OAuth2/GrantType/RefreshToken.php) class. So, by default a new refresh token is not
issued, but you can easily configure this to do so by setting `'always_issue_new_refresh_token' => true`

If you want to support more than one grant type it is possible to add more when the Server object is created:

```php
$server->addGrantType(new OAuth2\GrantType\UserCredentials($storage));
$server->addGrantType(new OAuth2\GrantType\RefreshToken($storage));
$server->addGrantType(new OAuth2\GrantType\AuthorizationCode($storage));
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

Most OAuth2 APIs will have endpoints for `Authorize Requests`, `Token Requests`, and `Resource Requests`.  The `OAuth2\Server` object has methods to handle each of these requests.

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

The Response Object
-------------------

The response object serves the purpose of making your server OAuth2 compliant.  It will set the appropriate status codes, headers,
and response body for a valid or invalid oauth request.  To use it as it's simplest level, just send the output and exit:

```php
$request = OAuth2\Request::createFromGlobals();
$response = new OAuth2\Response();

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

In this library, scope is handled by implementing `OAuth2\Storage\ScopeInterface`. This can be done using your own
implementation, or by taking advantage of the existing `OAuth2\Storage\Memory` class:

```php
// configure your available scopes
$defaultScope = 'basic';
$supportedScopes = array(
  'basic',
  'postonwall',
  'accessphonenumber'
);
$memory = new OAuth2\Storage\Memory(array(
  'default_scope' => $defaultScope,
  'supported_scopes' => $supportedScopes
));
$scopeUtil = new OAuth2\Scope($memory);

$server->setScopeUtil($scopeUtil);
```

This is the simplest way, but scope can by dynamically configured as well:

```php
// configure your available scopes
$doctrine = Doctrine_Core::getTable('OAuth2Scope');
$scopeUtil = new OAuth2\Scope($doctrine);

$server->setScopeUtil($scopeUtil);
```

This example assumes the class being used implements `OAuth2\Storage\ScopeInterface`:

```php
class OAuth2ScopeTable extends Doctrine_Table implements OAuth2\Storage\ScopeInterface
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
$request = OAuth2\Request::createFromGlobals();
$response = new OAuth2\Response();
$scopeRequired = 'postonwall'; // this resource requires "postonwall" scope
if (!$server->verifyResourceRequest($request, $response, $scopeRequired)) {
  // if the scope required is different from what the token allows, this will send a "401 insufficient_scope" error
  $response->send();
}
```

####Customizing your scope

As the implementation of "scope" can be significantly different for each application, providing a different class other than
OAuth2\Scope can be beneficial.  Implement `OAuth2\ScopeInterface` in a custom class to fully customize.

State
-----

The `state` parameter is required by default for authorize redirects.  This is the equivalent of a `CSRF` token, and provides
session validation for your Authorize request.  See the [OAuth2.0 Spec](http://tools.ietf.org/html/rfc6749#section-4.1.1)
for more information on state.

This is enabled by default for security purposes, but you can remove this requirement when you configure your server:

```php
// on creation
$server = new OAuth2\Server($storage, array('enforce_state' => false));

// or after creation
$server = new OAuth2\Server();
$server->setConfig('enforce_state', false);
```

Contact
-------

The best way to get help and ask questions is to [file an issue](https://github.com/bshaffer/oauth2-server-php/issues/new).  This will
help answer questions for others as well.

If for whatever reason filing an issue does not make sense, contact Brent Shaffer (bshafs <at> gmail <dot> com)
