<?php

require_once(dirname(__FILE__).'/../src/OAuth2/Autoloader.php');
OAuth2_Autoloader::register();

// register test classes
OAuth2_Autoloader::register(dirname(__FILE__).'/lib');
