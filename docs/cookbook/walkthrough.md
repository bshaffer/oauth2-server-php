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

### Associating local users with access tokens

Once you've authenticated a user and issued an access token (such as with the above Authorize Controller example),
you'll probably want to know which user an access token applies to when it is used. Have a look at the
[User ID documentation](../userid.md) for information on how to do this.

### Testing your Authorize Controller with an external client

If you want to test the authorize controller using a "real" client, check out the
[Google OAuth2 Playground example](google-playground.md)
