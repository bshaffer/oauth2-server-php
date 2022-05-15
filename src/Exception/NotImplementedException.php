<?php
namespace OAuth2\Exception;

/**
 * Not Implemented Exception
 * 
 * http://php.net/manual/en/language.exceptions.extending.php
 */
class NotImplementedException extends \Exception
{
    // Redefine the exception so message isn't optional
    public function __construct(string $message, int $code = 0, \Exception $previous = null) {
        // some code
    
        // make sure everything is assigned properly
        parent::__construct($message, $code, $previous);
    }

    // custom string representation of object
    public function __toString() {
        return __CLASS__ . ": [{$this->code}]: {$this->message}\n";
    }

}