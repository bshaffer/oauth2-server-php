oauth2-server-php
=================

[![Build Status](https://secure.travis-ci.org/bshaffer/oauth2-server-php.png)](http://travis-ci.org/bshaffer/oauth2-server-php)

An OAuth2.0 Server in PHP! [View the Full Working Demo](http://brentertainment.com/oauth2) ([code](https://github.com/bshaffer/oauth2-demo-php))

Requirements
------------

PHP 5.3.9+ is required for this library.  However, we have a [stable release](https://github.com/bshaffer/oauth2-server-php/tree/v0.9) and [developerment branch](https://github.com/bshaffer/oauth2-server-php/tree/php5.2-develop) for PHP <5.3.8 and PHP 5.2.x as well.

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

Contact
-------

The best way to get help and ask questions is to [file an issue](https://github.com/bshaffer/oauth2-server-php/issues/new).  This will
help answer questions for others as well.

If for whatever reason filing an issue does not make sense, contact Brent Shaffer (bshafs <at> gmail <dot> com)
