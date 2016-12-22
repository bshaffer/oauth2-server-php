<?php

namespace OAuth2\Storage\Phalcon\Models;

use OAuth2\Storage\Phalcon\Phalcon;

class OauthRefreshTokens extends \Phalcon\Mvc\Model
{
    /**
     *
     * @var string
     */
    public $refresh_token;

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
     * @return OauthRefreshTokens[]
     */
    public static function find($parameters = null)
    {
        return parent::find($parameters);
    }

    /**
     * Allows to query the first record that match the specified conditions
     *
     * @param mixed $parameters
     * @return OauthRefreshTokens
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
        $this->setSource("'" . $this->getDI()->get(Phalcon::KEY_PHALCON_CONFIG_ARRAY)['refresh_token_table'] . "'");
        $this->belongsTo('user_id', 'OAuth2\Storage\Phalcon\Models\OauthUsers', 'username');
        $this->belongsTo('client_id', 'OAuth2\Storage\Phalcon\Models\OauthClients', 'client_id');
    }

    /**
     * Returns table name mapped in the model.
     *
     * @return string
     */
    public function getSource()
    {
        return $this->getDI()->get(Phalcon::KEY_PHALCON_CONFIG_ARRAY)['refresh_token_table'];
    }
}