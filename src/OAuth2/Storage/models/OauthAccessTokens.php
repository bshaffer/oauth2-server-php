<?php

namespace OAuth2\Storage\Models;

use Phalcon\Mvc\Model\Behavior\SoftDelete;

class OauthAccessTokens extends \Phalcon\Mvc\Model
{

    const VALID = 1;
    const INVALID = 0;
    
    /**
     *
     * @var string
     */
    public $access_token;

    /**
     *
     * @var boolean
     */
    public $valid;

    /**
     *
     * @var string
     */
    public $client_id;

    /**
     *
     * @var string
     */
    public $client_ip;

    /**
     *
     * @var string
     */
    public $client_useragent;

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
     * Initialize method for model.
     */
    public function initialize()
    {
        $this->keepSnapshots(true);
        $this->setSource("'oauth__access_tokens'");
        $this->belongsTo('user_id', 'OAuth2\Storage\Models\OauthUsers', 'username', array("alias" => "User"));
        $this->belongsTo('client_id', 'OAuth2\Storage\Models\OauthClients', 'client_id', array("alias" => "Client"));
        $this->addBehavior(
            new SoftDelete(
                array(
                    'field' => 'status',
                    'value' => InventoryTransfers::DELETED
                )
            )
        );
    }


    /**
     * Returns table name mapped in the model.
     *
     * @return string
     */
    public function getSource()
    {
        return 'oauth__access_tokens';
    }

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
     * @param mixed $parameters
     * @return \OAuth2\Storage\Models\OauthUsers
     */
    public function getUser($parameters = null){
        return $this->getRelated('User', $parameters);
    }

    /**
     * @param mixed $parameters
     * @return \OAuth2\Storage\Models\OauthClients
     */
    public function getClient($parameters = null){
        return $this->getRelated('Client', $parameters);
    }

}
