<?php

namespace OAuth2\Encryption;

use OAuth2\Storage\Bootstrap;

class JwtTest extends \PHPUnit_Framework_TestCase
{
    private $privateKey;

    public function setUp()
    {
        $this->privateKey = <<<EOD
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC5/SxVlE8gnpFqCxgl2wjhzY7ucEi00s0kUg3xp7lVEvgLgYcA
nHiWp+gtSjOFfH2zsvpiWm6Lz5f743j/FEzHIO1owR0p4d9pOaJK07d01+RzoQLO
IQAgXrr4T1CCWUesncwwPBVCyy2Mw3Nmhmr9MrF8UlvdRKBxriRnlP3qJQIDAQAB
AoGAVgJJVU4fhYMu1e5JfYAcTGfF+Gf+h3iQm4JCpoUcxMXf5VpB9ztk3K7LRN5y
kwFuFALpnUAarRcUPs0D8FoP4qBluKksbAtgHkO7bMSH9emN+mH4le4qpFlR7+P1
3fLE2Y19IBwPwEfClC+TpJvuog6xqUYGPlg6XLq/MxQUB4ECQQDgovP1v+ONSeGS
R+NgJTR47noTkQT3M2izlce/OG7a+O0yw6BOZjNXqH2wx3DshqMcPUFrTjibIClP
l/tEQ3ShAkEA0/TdBYDtXpNNjqg0R9GVH2pw7Kh68ne6mZTuj0kCgFYpUF6L6iMm
zXamIJ51rTDsTyKTAZ1JuAhAsK/M2BbDBQJAKQ5fXEkIA+i+64dsDUR/hKLBeRYG
PFAPENONQGvGBwt7/s02XV3cgGbxIgAxqWkqIp0neb9AJUoJgtyaNe3GQQJANoL4
QQ0af0NVJAZgg8QEHTNL3aGrFSbzx8IE5Lb7PLRsJa5bP5lQxnDoYuU+EI/Phr62
niisp/b/ZDGidkTMXQJBALeRsH1I+LmICAvWXpLKa9Gv0zGCwkuIJLiUbV9c6CVh
suocCAteQwL5iW2gA4AnYr5OGeHFsEl7NCQcwfPZpJ0=
-----END RSA PRIVATE KEY-----
EOD;
    }

    /** @dataProvider provideClientCredentials */
    public function testJwtUtil($client_id, $client_key)
    {
        $jwtUtil = new Jwt();
        $params = $this->getJWTParams(null, null, null, $client_id);

        $encoded = $jwtUtil->encode($params, $this->privateKey, 'RS256');

        $payload = $jwtUtil->decode($encoded, $client_key);

        $this->assertEquals($params, $payload);
    }

    public function provideClientCredentials()
    {
        $storage = Bootstrap::getInstance()->getMemoryStorage();
        $client_id  = 'Test Client ID';
        $client_key = $storage->getClientKey($client_id, "testuser@ourdomain.com");
        return array(
            array($client_id, $client_key),
        );
    }

    /**
     * Generates a JWT
     * @param $exp The expiration date. If the current time is greater than the exp, the JWT is invalid.
     * @param $nbf The "not before" time. If the current time is less than the nbf, the JWT is invalid.
     * @param $sub The subject we are acting on behalf of. This could be the email address of the user in the system.
     * @param $iss The issuer, usually the client_id.
     * @return string
     */
    private function getJWTParams($exp = null, $nbf = null, $sub = null, $iss = 'Test Client ID', $scope = null)
    {
        //Since PHP 5.2 does not have OpenSSL support on Travis CI, we will test it using the HS256 algorithm
        //We also provided PHP 5.2 specific data for it in storage.json
        if (version_compare(PHP_VERSION, '5.3.3') <= 0) {
            // add "5.2" identifier onto the client name
            $iss .= ' PHP-5.2';
        }

        if (!$exp) {
            $exp = time() + 1000;
        }

        if (!$sub) {
            $sub = "testuser@ourdomain.com";
        }

        $params = array(
            'iss' => $iss,
            'exp' => $exp,
            'iat' => time(),
            'sub' => $sub,
            'aud' => 'http://myapp.com/oauth/auth',
            'scope' => $scope,
        );

        if ($nbf) {
            $params['nbf'] = $nbf;
        }

        return $params;
    }
}
