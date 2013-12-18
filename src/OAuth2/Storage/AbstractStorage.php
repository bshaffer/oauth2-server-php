<?php

namespace OAuth2\Storage;

use Zend\Crypt\Password\Bcrypt;

/**
 * Abstract Storage
 *
 * NOTE: Passwords are stored using bcrypt
 * @see http://framework.zend.com/manual/2.2/en/modules/zend.crypt.password.html#bcrypt
 */
abstract class AbstractStorage
{
    const BCRYPT_COST = '10';

    protected $bcrypt;

    public function __construct($config = array())
    {
        $this->bcrypt = new Bcrypt();
        if (isset($config['bcrypt_cost'])) {
            $this->bcrypt->setCost($config['bcrypt_cost']);
        } else {
            $this->bcrypt->setCost(self::BCRYPT_COST);
        }
    }

    /**
     * Check the validity of credential (secret or password)
     *
     * @param string $credential
     * @param string $valueToCheck
     * @return boolean
     */
    public function checkCredential($credential, $valueToCheck)
    {
        // backward compatibility support: plaintext, sha1 and bcrypt
        if ($credential === $valueToCheck) {
            return true;
        }
        if ($credential === sha1($valueToCheck)) {
            return true;
        }
        try {
            $result = $this->bcrypt->verify($valueToCheck, $credential);
        } catch (\Zend\Crypt\Password\Exception\RuntimeException $e) {
            return false;
        }
        return $result;

    }
 
}
