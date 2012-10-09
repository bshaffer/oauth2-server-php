<?php

require_once(dirname(__FILE__).'/../src/OAuth2/Autoloader.php');
OAuth2_Autoloader::register();

// register test classes
OAuth2_Autoloader::register(dirname(__FILE__));

class OAuth2_Test_Autoloader
{
    /**
     * Registers AdobeDigitalMarketing_Autoloader as an SPL autoloader.
     */
    static public function register()
    {
        ini_set('unserialize_callback_func', 'spl_autoload_call');
        spl_autoload_register(array(new self, 'autoload'));
    }

    /**
     * Handles autoloading of classes.
     *
     * @param  string  $class  A class name.
     *
     * @return boolean Returns true if the class has been loaded
     */
    static public function autoload($class)
    {
        if (0 !== strpos($class, 'OAuth2')) {
            return;
        }

        if (file_exists($file = dirname(__FILE__).'/../'.str_replace('_', '/', $class).'.php')) {
            require $file;
        }
    }
}
