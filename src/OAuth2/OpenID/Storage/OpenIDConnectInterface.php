<?php
namespace OAuth2\OpenID\Storage;

interface OpenIDConnectInterface {
    
    /**
     * 
     * @param type $userId
     * @param type $clientId
     * @return array|null An associative array as below, and return NULL if not found:
     * @code array(
     *     'openid' => 'openid'
     *     'user_id' => 'user id',
     *     'client_id' => 'client_id'
     * )
     */
    public function getOpenID($userId, $clientId, $type);

    public function setOpenID($openid, $userId, $clientId);
}