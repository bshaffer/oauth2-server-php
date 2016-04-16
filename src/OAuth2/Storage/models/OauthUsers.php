<?php

namespace OAuth2\Storage\Models;

use Phalcon\Mvc\Model\Behavior\SoftDelete;
use Phalcon\Mvc\Model\Validator\Email as Email;

class OauthUsers extends \Phalcon\Mvc\Model
{

    const ACTIVE = 0;
    const LOCKED = 1;
    const DELETED = 2;

    /**
     *
     * @var string
     */
    public $id;

    /**
     *
     * @var int
     */
    public $status;

    /**
     *
     * @var string
     */
    public $username;

    /**
     *
     * @var string
     */
    public $password;

    /**
     *
     * @var string
     */
    public $first_name;

    /**
     *
     * @var string
     */
    public $last_name;

    /**
     *
     * @var string
     */
    public $email;

    /**
     *
     * @var integer
     */
    public $email_verified;

    /**
     *
     * @var string
     */
    public $scope;

    /**
     * Allows to query a set of records that match the specified conditions
     *
     * @param mixed $parameters
     * @return OauthUsers[]
     */
    public static function find($parameters = null)
    {
        return parent::find($parameters);
    }

    /**
     * Allows to query the first record that match the specified conditions
     *
     * @param mixed $parameters
     * @return OauthUsers
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
        $this->keepSnapshots(true);
        $this->setSource("'oauth__users'");
        $this->hasMany('username', 'OAuth2\Storage\Models\OauthAccessTokens', 'user_id', array("alias" => "AccessTokens"));
        $this->hasMany('username', 'OAuth2\Storage\Models\OauthRefreshTokens', 'user_id', array("alias" => "RefreshTokens"));
        $this->hasMany('username', 'OAuth2\Storage\Models\InventoryLocUsers', 'username', array("alias" => "LocationsUsers"));
        $this->hasMany('username', 'OAuth2\Storage\Models\InventoryAccountsUsers', 'username', array("alias" => "AccountsUsers"));
        $this->hasManyToMany('username', 'OAuth2\Storage\Models\InventoryAccountsUsers', 'username', 'account_id', 'OAuth2\Storage\Models\InventoryAccounts', array("alias" => "Accounts"));
        $this->hasManyToMany('username', 'OAuth2\Storage\Models\InventoryLocationsUsers', 'username', 'location_id', 'OAuth2\Storage\Models\InventoryLocations', array("alias" => "Locations"));
        $this->hasMany('username', 'OAuth2\Storage\Models\InventoryTransfers', 'username', array("alias" => "Transfers"));
        $this->hasMany('username', 'OAuth2\Storage\Models\InventoryTransfersLogs', 'username', array("alias" => "TransfersLogs"));
        $this->hasMany('username', 'OAuth2\Storage\Models\InventorySales', 'username', array("alias" => "Sales"));
        $this->hasMany('username', 'OAuth2\Storage\Models\InventorySalesLogs', 'username', array("alias" => "SalesLogs"));
        $this->hasOne('username', 'OAuth2\Storage\Models\OauthAdmins', 'username', array("alias" => "Admin"));
        $this->addBehavior(
            new SoftDelete(
                array(
                    'field' => 'status',
                    'value' => OauthUsers::DELETED
                )
            )
        );
    }

    /**
     * Validations and business logic
     *
     * @return boolean
     */
    public function validation()
    {
        $this->validate(
            new Email(
                array(
                    'field' => 'email',
                    'required' => true,
                )
            )
        );

        if ($this->validationHasFailed() == true) {
            return false;
        }

        return true;
    }

    /**
     * Returns table name mapped in the model.
     *
     * @return string
     */
    public function getSource()
    {
        return 'oauth__users';
    }

    /**
     * @param mixed $parameters
     * @return \OAuth2\Storage\Models\OauthAccessTokens[]
     */
    public function getAccessTokens($parameters = null)
    {
        return $this->getRelated('AccessTokens', $parameters);
    }

    /**
     * @param mixed $parameters
     * @return \OAuth2\Storage\Models\OauthRefreshTokens[]
     */
    public function getRefreshTokens($parameters = null)
    {
        return $this->getRelated('RefreshTokens', $parameters);
    }

    /**
     * @param mixed $parameters
     * @return \OAuth2\Storage\Models\InventoryLocUsers[]
     */
    public function getLocUsers($parameters = null)
    {
        return $this->getRelated('LocationsUsers', $parameters);
    }

    /**
     * @param mixed $parameters
     * @return \OAuth2\Storage\Models\InventoryLocUsers[]
     */
    public function getAccountsUsers($parameters = null)
    {
        return $this->getRelated('AccountsUsers', $parameters);
    }

    /**
     * @param mixed $parameters
     * @return \OAuth2\Storage\Models\InventorySales[]
     */
    public function getSales($parameters = null)
    {
        return $this->getRelated('Sales', $parameters);
    }

    /**
     * @param mixed $parameters
     * @return \OAuth2\Storage\Models\InventorySalesLogs[]
     */
    public function getSalesLogs($parameters = null)
    {
        return $this->getRelated('SalesLogs', $parameters);
    }

    /**
     * @param mixed $parameters
     * @return \OAuth2\Storage\Models\InventoryTransfersLogs[]
     */
    public function getTransfersLogs($parameters = null)
    {
        return $this->getRelated('TransfersLogs', $parameters);
    }

    /**
     * Returns true if the user is either a DB admin or a normal admin
     * @return bool
     */
    public function isAdmin()
    {
        if($this->isDbAdmin())
            return true;

        $admin = OauthAdmins::findFirst("username = '{$this->username}'");
        if ($admin != false)
            return true;
        else
            return false;
    }

    /**
     * @return bool
     */
    public function isDbAdmin()
    {
        $admin = OauthDbAdmins::findFirst("username = '{$this->username}'");
        if ($admin != false)
            return true;
        else
            return false;
    }

    /**
     * @param mixed $parameters
     * @return \OAuth2\Storage\Models\InventoryAccounts[]
     */
    public function getAccounts($parameters = null){
        return $this->getRelated('Accounts', $parameters);
    }

    /**
     * @param mixed $parameters
     * @return \OAuth2\Storage\Models\InventoryLocations[]
     */
    public function getLocations($parameters = null){
        return $this->getRelated('Locations', $parameters);
    }

    /**
     * @param integer $location_id
     * @return InventoryLocations[]
     */
    public function getAllowedLocations($location_id = null)
    {
        if($this->isAdmin())
            return InventoryLocations::find(is_null($location_id) ?: $location_id);

        $locationsUsers = is_null($location_id) ? InventoryLocUsers::find("username = '{$this->username}'") : InventoryLocUsers::find("loc_id = '{$location_id}' AND username = '{$this->username}'");
        $locationsArray = array();
        foreach ($locationsUsers as $locationsUser) {
            array_push($locationsArray, $locationsUser->getLocation());
        }
        return $locationsArray;
    }

    /**
     * @param integer $account_id
     * @return InventoryAccounts[]
     */
    public function getAllowedAccounts($account_id = null)
    {
        if($this->isAdmin())
            return InventoryAccounts::find(is_null($account_id) ?: $account_id);

        $accountsUsers = is_null($account_id) ? InventoryAccountsUsers::find("username = '{$this->username}'") : InventoryAccountsUsers::find("account_id = '{$account_id}' AND username = '{$this->username}'");
        $accountsArray = array();
        foreach ($accountsUsers as $locationsUser) {
            array_push($accountsArray, $locationsUser->getAccount());
        }
        return $accountsArray;
    }
}
