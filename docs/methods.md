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
