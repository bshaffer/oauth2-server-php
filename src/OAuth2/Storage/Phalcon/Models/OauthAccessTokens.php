<?php

namespace OAuth2\Storage\Phalcon\Models;

use OAuth2\Storage\Phalcon\Phalcon;

class OauthAccessTokens extends \Phalcon\Mvc\Model
{
    /**
     *
     * @var string
     */
    public $access_token;

    /**
     *
     * @var string
     */
    public $client_id;

    /**
     *
     * @var string
     */
    public $user_id;

    /**
     *
     * @var string
     */
    public $expires;

    /**
     *
     * @var string
     */
    public $scope;

    /**
     * Allows to query a set of records that match the specified conditions
     *
     * @param mixed $parameters
     * @return OauthAccessTokens[]
     */
    public static function find($parameters = null)
    {
        return parent::find($parameters);
    }

    /**
     * Allows to query the first record that match the specified conditions
     *
     * @param mixed $parameters
     * @return OauthAccessTokens
     */
    public static function findFirst($parameters = null)
    {
        return parent::findFirst($parameters);
    }

    /**
     * Initialize method for model.
     */
    public function initialize()
    {
        $this->setSource("'" . $this->getDI()->get(Phalcon::KEY_PHALCON_CONFIG_ARRAY)['access_token_table'] . "'");
        $this->belongsTo('user_id', 'OAuth2\Storage\Phalcon\Models\OauthUsers', 'username', array("alias" => "User"));
        $this->belongsTo('client_id', 'OAuth2\Storage\Phalcon\Models\OauthClients', 'client_id', array("alias" => "Client"));
    }

    /**
     * Returns table name mapped in the model.
     *
     * @return string
     */
    public function getSource()
    {
        return $this->getDI()->get(Phalcon::KEY_PHALCON_CONFIG_ARRAY)['access_token_table'];
    }

    /**
     * @param mixed $parameters
     * @return \OAuth2\Storage\Phalcon\Models\OauthUsers
     */
    public function getUser($parameters = null)
    {
        return $this->getRelated('User', $parameters);
    }

    /**
     * @param mixed $parameters
     * @return \OAuth2\Storage\Phalcon\Models\OauthClients
     */
    public function getClient($parameters = null)
    {
        return $this->getRelated('Client', $parameters);
    }

}