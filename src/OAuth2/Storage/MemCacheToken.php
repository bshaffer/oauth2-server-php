<?php
namespace OAuth2\Storage;

use Memcache;

class MemCacheToken implements AccessTokenInterface
{
    protected $storage;
    protected $memcache;

    public function __construct(AccessTokenInterface $storage)
    {
        $this->storage = $storage;

        $this->memcache = new Memcache;
        $this->memcache->connect('localhost', 11211);
    }

    public function getAccessToken($access_token)
    {
        $cacheKey = 'storage-'.$access_token;           

        # Try and get from memory
        $accessToken = $this->memcache->get($cacheKey);

        # We have some data
        if(!empty($accessToken)) {
            return $accessToken;
        }

        $accessToken = $this->storage->getAccessToken('access_token');
        $this->memcache->set($cacheKey, $accessToken, 0, strtotime($accessToken['expires']));

        return $accessToken;
    }

    public function setAccessToken($oauth_token, $client_id, $user_id, $expires, $scope = null)
    {
        $cacheKey = 'storage-'.$oauth_token;           

        $this->storage->setAccessToken($oauth_token, $client_id, $user_id, $expires, $scope);
        $updatedAccessToken = $this->storage->getAccessToken($oauth_token);

        $result = $this->memcache->replace($cacheKey, $updatedAccessToken, 0, $expires);
        if( $result == false ) 
        { 
            $result = $this->memcache->set($cacheKey, $updatedAccessToken, 0, $expires);
        }

    }
}
