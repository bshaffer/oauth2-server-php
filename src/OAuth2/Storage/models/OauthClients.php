<?php

namespace OAuth2\Storage\Models;

class OauthClients extends \Phalcon\Mvc\Model
{

    /**
     *
     * @var string
     */
    public $client_id;

    /**
     *
     * @var string
     */
    public $client_secret;

    /**
     *
     * @var string
     */
    public $redirect_uri;

    /**
     *
     * @var string
     */
    public $grant_types;

    /**
     *
     * @var string
     */
    public $scope;

    /**
     *
     * @var string
     */
    public $user_id;

    /**
     * Initialize method for model.
     */
    public function initialize()
    {
        $this->setSource("'oauth__clients'");
        $this->belongsTo('user_id', 'OAuth2\Storage\Models\OauthUsers', 'username', array("alias" => "User"));
    }

    /**
     * Returns table name mapped in the model.
     *
     * @return string
     */
    public function getSource()
    {
        return 'oauth__clients';
    }

    /**
     * Allows to query a set of records that match the specified conditions
     *
     * @param mixed $parameters
     * @return OauthClients[]
     */
    public static function find($parameters = null)
    {
        return parent::find($parameters);
    }

    /**
     * Allows to query the first record that match the specified conditions
     *
     * @param mixed $parameters
     * @return OauthClients
     */
    public static function findFirst($parameters = null)
    {
        return parent::findFirst($parameters);
    }

    /**
     * @param mixed $parameters
     * @return OauthUsers
     */
    public function getUser($parameters = null){
        return $this->getRelated('User', $parameters);
    }
}
