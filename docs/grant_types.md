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
