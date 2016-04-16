<?php

namespace OAuth2\Storage\Models;

class OauthDbAdmins extends \Phalcon\Mvc\Model
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
        $this->setSource("'oauth__dbadmins'");
        $this->belongsTo('username', 'OAuth2\Storage\Models\OauthUsers', 'username', array('alias' => 'User'));
    }

    /**
     * Returns table name mapped in the model.
     *
     * @return string
     */
    public function getSource()
    {
        return 'oauth__dbadmins';
    }

    /**
     * Allows to query a set of records that match the specified conditions
     *
     * @param mixed $parameters
     * @return OauthDbAdmins[]
     */
    public static function find($parameters = null)
    {
        return parent::find($parameters);
    }

    /**
     * Allows to query the first record that match the specified conditions
     *
     * @param mixed $parameters
     * @return OauthDbAdmins
     */
    public static function findFirst($parameters = null)
    {
        return parent::findFirst($parameters);
    }

    /**
     * @param mixed $parameters
     * @return OauthUsers
     */
    public function getUser($parameters = null)
    {
        return $this->getRelated('User', $parameters);
    }

}
