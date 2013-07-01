### Associating local users with access tokens

Once you've authenticated a user and issued an access token (such as with an Authorize Controller),
you'll probably want to know which user an access token applies to when it is used.

You can do this by using the optional user_id parameter of `handleAuthorizeRequest`:

```php
$userid = 1234; // A value on your server that identifies the user
$server->handleAuthorizeRequest($request, $response, $is_authorized, $userid);
```
   
That will save the user ID into the database with the access token. When the token is used by a client, you
can retrieve the associated ID:

```php
if (!$server->verifyResourceRequest(OAuth2_Request::createFromGlobals(), new OAuth2_Response())) {
    $server->getResponse()->send();
    die;
}
 
$token = $server->getAccessTokenData(OAuth2_Request::createFromGlobals(), new OAuth2_Response());
echo "User ID associated with this token is {$token['user_id']}";
```
