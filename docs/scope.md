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