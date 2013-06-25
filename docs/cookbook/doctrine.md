Integrating with Doctrine
=========================

Create Client and Access Token Storage
------------------------------------------

To integrate doctrine into your project, first set up your models.  Let's start with just the Client and Access Token models:

```yaml
OAuthClient:
  tableName:      oauth_client
  columns:
    client_identifier:
      type:       string(50)
      notnull:    true
    client_secret:
      type:       char(20)
      notnull:    true
    redirect_uri:
      type:       string(255)
      notnull:    true
      default:    ""

OAuthAccessToken:
  tableName:      oauth_access_token
  columns:
    token:
      type:       char(40)
      notnull:    true
      unique:     true
    client_identifier:
      type:       string(50)
      notnull:    true
    user_identifier:
      type:       string(100)
      notnull:    true
    expires:
      type:       timestamp
      notnull:    true
    scope:
      type:       string(50)
      notnull:    false
  relations:
    Client:
      local:        client_identifier
      foreign:      client_identifier
      class:        OAuthClient
      foreignAlias: AccessTokens
      onDelete:     CASCADE
      onUpdate:     CASCADE
```

Once you've generated the models off this schema, you will have an `OAuthClient` and `OAuthCleintTable` class
file, as well as an `OAuthAccessToken` and `OAuthAccessTokenTable` object.

Implement `OAuth2\Storage\ClientCredentialsInterface` on the `OAuthClientTable` class:

```php
class OAuthClientTable extends PluginOAuthClientTable implements OAuth2\Storage\ClientCredentialsInterface
{
    public function getClientDetails($client_id)
    {
        $client = $this->createQuery()
            ->where('client_identifier = ?', $client_id)
            ->fetchOne(array(), Doctrine::HYDRATE_ARRAY);

        return $client;
    }

    public function checkClientCredentials($client_id, $client_secret = NULL)
    {
        $client = $this->getClientDetails($client_id);

        if ($client) {
            return $client['client_secret'] === sha1($client_secret);
        }
        return false;
    }

    public function checkRestrictedGrantType($client_id, $grant_type)
    {
        // we do not support different grant types per client in this example
        return true;
    }
}
```

Now implement `OAuth2\Storage\AccessTokenInterface` on the `OAuthAccessTokenTable` class:

```php
class OAuthAccessTokenTable extends PluginOAuthAccessTokenTable implements OAuth2\Storage\AccessTokenInterface
{
    public function getAccessToken($oauth_token)
    {
        $token = $this->createQuery()
            ->where('token = ?', $oauth_token)
            ->fetchOne(array(), Doctrine_Core::HYDRATE_ARRAY);

        if ($token) {
            return array(
               'token'     => $token['token'],
               'client_id' => $token['client_identifier'],
               'expires'   => strtotime($token['expires']),
               'scope'     => $token['scope'],
               'user_id'   => $token['user_identifier'],
            );
        }
    }

    public function setAccessToken($oauth_token, $client_id, $user_id, $expires, $scope = null)
    {
        $token = new OAuthAccessToken();
        $token->fromArray(array(
           'token'              => $oauth_token,
           'client_identifier'  => $client_id,
           'user_identifier'    => $user_id,
           'expires'            => date('Y-m-d H:i:s', $expires),
           'scope'              => $scope,
        ));

        $token->save();
    }
}
```

Good job!  Now, when you create your `OAuth\Server` object, pass these tables in:

```php
$clientStore = Doctrine::getTable('OAuthClient');
$tokenStore  = Doctrine::getTable('OAuthAccessToken');

// Pass the doctrine storage objects to the OAuth2 server class
$server = new OAuth2\Server(array('client_credentials' => $clientStore, 'access_token' => $tokenStore));
```

You've done it!  You've integrated your server with Doctrine!  You can go to town using it, but
since you've only passed it a `client_credentials` and `access_token` storage object, you can only
use the `client_credentials` grant type:


```php
// will only be able to handle token requests when "grant_type=client_credentials".
$server->addGrantType(new OAuth2\GrantType\ClientCredentials($clientStorage));

// handle the request
$server->handleTokenRequest(OAuth2\Request::createFromGlobals())->send();
```

Add Authorization Code and Refresh Token Storage
------------------------------------------------

So lets make our application a little more exciting.  Add the following to your schema and
generate the class files:

```yaml
OAuthAuthorizationCode:
  tableName:      oauth_authorization_code
  columns:
    code:
      type:       char(40)
      notnull:    true
      unique:     true
    client_identifier:
      type:       string(50)
      notnull:    true
    expires:
      type:       timestamp
      notnull:    true
    user_identifier:
      type:       string(100)
      notnull:    true
    redirect_uri:
      type:       string(200)
      notnull:    true
    scope:
      type:       string(50)
      notnull:    false
  relations:
    Client:
      local:        client_identifier
      foreign:      client_identifier
      class:        OAuthClient
      foreignAlias: AuthorizationCodes
      onDelete:     CASCADE
      onUpdate:     CASCADE

OAuthRefreshToken:
  tableName:      oauth_refresh_token
  columns:
    refresh_token:
      type:       char(40)
      notnull:    true
      unique:     true
    client_identifier:
      type:       string(50)
      notnull:    true
    user_identifier:
      type:       string(100)
      notnull:    true
    expires:
      type:       timestamp
      notnull:    true
    scope:
      type:       string(50)
      notnull:    false
  relations:
    Client:
      local:        client_identifier
      foreign:      client_identifier
      class:        OAuthClient
      foreignAlias: RefreshTokens
      onDelete:     CASCADE
      onUpdate:     CASCADE
```

Now we can implement two more interfaces, `OAuth2\Storage\AuthorizationCodeInterface` and
`OAuth2\Storage\RefreshTokenInterface`.  This will allow us to use their correspoding grant
types as well.

Implement `OAuth2\Storage\AuthorizationCodeInterface` on the `OAuthAuthorizationCodeTable` class:


```php
class OAuthAuthorizationCodeTable extends PluginOAuthAuthorizationCodeTable implements OAuth2\Storage\AuthorizationCodeInterface
{
    public function getAuthorizationCode($code)
    {
        $auth_code = $this->createQuery()
            ->where('code = ?', $code)
            ->fetchOne(array(), Doctrine_Core::HYDRATE_ARRAY);

        if ($auth_code) {
            return array(
               'code'         => $auth_code['code'],
               'client_id'    => $auth_code['client_identifier'],
               'user_id'      => $auth_code['web_service_username'],
               'redirect_uri' => $auth_code['redirect_uri'],
               'expires'      => strtotime($auth_code['expires']),
               'scope'        => $auth_code['scope'],
            );
        }
        return null;
    }

    public function setAuthorizationCode($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null)
    {
        $auth_code = new OAuthAuthorizationCode();
        $auth_code->fromArray(array(
           'code'                 => $code,
           'client_identifier'    => $client_id,
           'web_service_username' => $user_id,
           'redirect_uri'         => $redirect_uri,
           'expires'              => date('Y-m-d H:i:s', $expires),
           'scope'                => $scope,
        ));

        $auth_code->save();
    }

    public function expireAuthorizationCode($code)
    {
        return $this->createQuery()
            ->delete()
            ->where('code = ?', $code)
            ->execute();
    }
}
```

Implement `OAuth2\Storage\RefreshTokenInterface` on the `OAuthRefreshTokenTable` class:

```php
class OAuthRefreshTokenTable extends PluginOAuthRefreshTokenTable implements OAuth2\Storage\RefreshTokenInterface
{
    public function getRefreshToken($refresh_token)
    {
        $refresh_token = $this->createQuery()
            ->where('refresh_token = ?', $refresh_token)
            ->fetchOne(array(), Doctrine_Core::HYDRATE_ARRAY);

        if ($auth_code) {
            return array(
               'refresh_token' => $refresh_token['refresh_token'],
               'client_id'     => $refresh_token['client_identifier'],
               'user_id'       => $refresh_token['user_identifier'],
               'expires'       => strtotime($refresh_token['expires']),
               'scope'         => $refresh_token['scope'],
            );
        }
    }

    public function setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope = null)
    {
        $refresh_token = new OAuthRefreshToken();
        $refresh_token->fromArray(array(
           'code'              => $code,
           'client_identifier' => $client_id,
           'user_identifier'   => $user_id,
           'expires'           => date('Y-m-d H:i:s', $expires),
           'scope'             => $scope,
        ));

        $refresh_token->save();
    }

    public function unsetRefreshToken($refresh_token)
    {
        return $this->createQuery()
            ->delete()
            ->where('refresh_token = ?', $refresh_token)
            ->execute();
    }
}
```

Now we can add two more grant types onto our server:

```php
$clientStore  = Doctrine::getTable('OAuthClient');
$tokenStore   = Doctrine::getTable('OAuthAccessToken');
$codeStore    = Doctrine::getTable('OAuthAuthorizationCode');
$refreshStore = Doctrine::getTable('OAuthRefreshToken');

// Pass the doctrine storage objects to the OAuth2 server class
$server = new OAuth2\Server(array(
    'client_credentials' => $clientStore,
    'access_token'       => $tokenStore,
    'authorization_code' => $codeStore,
    'refresh_token'      => $refreshStore,
));

$server->addGrantType(new OAuth2\GrantType\ClientCredentials($clientStorage));
$server->addGrantType(new OAuth2\GrantType\AuthorizationCode($codeStorage));
$server->addGrantType(new OAuth2\GrantType\RefreshToken($refreshStorage));

// handle the request
$server->handleTokenRequest(OAuth2\Request::createFromGlobals())->send();
```

You've done it!!! Well, almost all of it.