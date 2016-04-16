<?php

namespace OAuth2\Storage\Models;

class OauthAdmins extends \Phalcon\Mvc\Model
{

    /**
     *
     * @var string
     */
    public $username;

    /**
     * Initialize method for model.
     */
    public function initialize()
    {
        $this->setSource("'oauth__admins'");
        $this->belongsTo('username', 'OAuth2\Storage\Models\OauthUsers', 'username', array('alias' => 'User'));
    }

    /**
     * Returns table name mapped in the model.
     *
     * @return string
     */
    public function getSource()
    {
        return 'oauth__admins';
    }

    /**
     * Allows to query a set of records that match the specified conditions
     *
     * @param mixed $parameters
     * @return OauthAdmins[]
     */
    public static function find($parameters = null)
    {
        return parent::find($parameters);
    }

    /**
     * Allows to query the first record that match the specified conditions
     *
     * @param mixed $parameters
     * @return OauthAdmins
     */
    public static function findFirst($parameters = null)
    {
        return parent::findFirst($parameters);
    }

    /**
     * @param mixed $parameters
     * @return \OAuth2\Storage\Models\OauthUsers
     */
    public function getUser($parameters = null){
        return $this->getRelated('User', $parameters);
    }
}
