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