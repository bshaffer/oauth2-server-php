<?php

namespace OAuth2\Encryption;

/**
 * @link https://github.com/F21/jwt
 * @author F21
 */
class Jwt implements EncryptionInterface
{

    public static $supportedAlgorithms = array(
        'HS256' => array('hash_hmac', 'sha256'),
        'HS384' => array('hash_hmac', 'sha384'),
        'HS512' => array('hash_hmac', 'sha512'),
        'RS256' => array('openssl', 'sha256', 'OPENSSL_ALGO_SHA256'),
        'RS384' => array('openssl', 'sha384', 'OPENSSL_ALGO_SHA384'),
        'RS512' => array('openssl', 'sha512', 'OPENSSL_ALGO_SHA512')
    );

    public function encode($payload, $key, $algo = 'HS256')
    {
        $header = $this->generateJwtHeader($payload, $algo);

        $segments = array(
            $this->urlSafeB64Encode(json_encode($header)),
            $this->urlSafeB64Encode(json_encode($payload))
        );

        $signing_input = implode('.', $segments);

        $signature = $this->sign($signing_input, $key, $algo);
        $segments[] = $this->urlsafeB64Encode($signature);

        return implode('.', $segments);
    }

    public function decode($jwt, $key = null, $allowed_algorithms = null)
    {
        if (!strpos($jwt, '.')) {
            return false;
        }

        $tks = explode('.', $jwt);

        if (count($tks) != 3) {
            return false;
        }

        list($headb64, $payloadb64, $cryptob64) = $tks;

        if (null === ($header = json_decode($this->urlSafeB64Decode($headb64), true))) {
            return false;
        }

        if (null === $payload = json_decode($this->urlSafeB64Decode($payloadb64), true)) {
            return false;
        }

        $sig = $this->urlSafeB64Decode($cryptob64);

        if (isset($key)) {
            if (!isset($header['alg'])) {
                return false;
            }

            if (!in_array($header['alg'], (array) $allowed_algorithms)){
                return false;
            }

            if (!$this->verifySignature($sig, "$headb64.$payloadb64", $key, $header['alg'])) {
                return false;
            }
        }

        return $payload;
    }

    private function verifySignature($signature, $input, $key, $algo = 'HS256')
    {
        list($function, $algorithm) = self::$supportedAlgorithms[$algo];
        switch ($function) {
            case 'hash_hmac':
                return $this->hash_equals(
                    $this->sign($input, $key, $algo),
                    $signature
                );

            case 'openssl':
                // use constants when possible, for HipHop support
                if(defined(self::$supportedAlgorithms[$algo][2])){
                    $algorithm = constant(self::$supportedAlgorithms[$algo][2]);
                }
                return @openssl_verify($input, $signature, $key, $algorithm) === 1;

            default:
                throw new \InvalidArgumentException("Unsupported or invalid signing algorithm.");
        }
    }

    private function sign($input, $key, $algo = 'HS256')
    {
        list($function, $algorithm) = self::$supportedAlgorithms[$algo];

        switch ($function) {
            case 'hash_hmac':
                return hash_hmac($algorithm, $input, $key, true);

            case 'openssl':
                if(defined(self::$supportedAlgorithms[$algo][2])){
                    $algorithm = constant(self::$supportedAlgorithms[$algo][2]);
                }
                return $this->generateRSASignature($input, $key, $algorithm);

            default:
                throw new \Exception("Unsupported or invalid signing algorithm.");
        }
    }

    private function generateRSASignature($input, $key, $algo)
    {
        if (!openssl_sign($input, $signature, $key, $algo)) {
            throw new \Exception("Unable to sign data.");
        }

        return $signature;
    }

    public function urlSafeB64Encode($data)
    {
        $b64 = base64_encode($data);
        $b64 = str_replace(array('+', '/', "\r", "\n", '='),
                array('-', '_'),
                $b64);

        return $b64;
    }

    public function urlSafeB64Decode($b64)
    {
        $b64 = str_replace(array('-', '_'),
                array('+', '/'),
                $b64);

        return base64_decode($b64);
    }

    public function getSupportedAlgorithms($type = null)
    {
        if ($type === null) {
            return array_keys(self::$supportedAlgorithms);
        }
        else {
            $filtered = array();
            foreach (self::$supportedAlgorithms as $alg => $method) {
                if ($type === 'RSA' && $alg[0] === 'R') {
                    $filtered[] = $alg;
                }
                else if ($type === 'HMAC' && $alg[0] === 'H') {
                    $filtered[] = $alg;
                }
            }
            return $filtered;
        }
    }

    /**
     * Override to create a custom header
     */
    protected function generateJwtHeader($payload, $algorithm)
    {
        return array(
            'typ' => 'JWT',
            'alg' => $algorithm,
        );
    }
    
    protected function hash_equals($a, $b)
    {
        if (function_exists('hash_equals')) {
            return hash_equals($a, $b);
        }
        $diff = strlen($a) ^ strlen($b);
        for ($i = 0; $i < strlen($a) && $i < strlen($b); $i++) {
            $diff |= ord($a[$i]) ^ ord($b[$i]);
        }
        return $diff === 0;
    }

}
