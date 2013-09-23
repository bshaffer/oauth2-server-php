<?php

namespace OAuth2\Encryption;

/**
 * @link https://github.com/F21/jwt
 * @author F21
 */
class Jwt implements EncryptionInterface
{
    public function encode($payload, $key, $algo = 'HS256')
    {
        $header = array('typ' => 'JWT', 'alg' => $algo);

        $segments = array(
            $this->urlsafeB64Encode(json_encode($header)),
            $this->urlsafeB64Encode(json_encode($payload))
        );

        $signing_input = implode('.', $segments);

        $signature = $this->sign($signing_input, $key, $algo);
        $segments[] = $this->urlsafeB64Encode($signature);

        return implode('.', $segments);
    }

    public function decode($jwt, $key = null, $verify = true)
    {
        $tks = explode('.', $jwt);

        if (count($tks) != 3) {
            return false;
        }

        list($headb64, $payloadb64, $cryptob64) = $tks;

        if (null === ($header = json_decode($this->urlsafeB64Decode($headb64), true))) {
            return false;
        }

        if (null === $payload = json_decode($this->urlsafeB64Decode($payloadb64), true)) {
            return false;
        }

        $sig = $this->urlsafeB64Decode($cryptob64);

        if ($verify) {
            if (!isset($header['alg'])) {
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
        switch($algo){
            case'HS256':
            case'HS384':
            case'HS512':
                return $this->sign($input, $key, $algo) === $signature;

            case 'RS256':
                return openssl_verify($input, $signature, $key, 'sha256') === 1;

            case 'RS384':
                return @openssl_verify($input, $signature, $key, 'sha384') === 1;

            case 'RS512':
                return @openssl_verify($input, $signature, $key, 'sha512') === 1;

            default:
                throw new \InvalidArgumentException("Unsupported or invalid signing algorithm.");
        }
    }

    private function sign($input, $key, $algo = 'HS256')
    {
        switch($algo){
            case 'HS256':
                return hash_hmac('sha256', $input, $key, true);

            case 'HS384':
                return hash_hmac('sha384', $input, $key, true);

            case 'HS512':
                return hash_hmac('sha512', $input, $key, true);

            case 'RS256':
                return $this->generateRSASignature($input, $key, 'sha256');

            case 'RS384':
                return $this->generateRSASignature($input, $key, 'sha384');

            case 'RS512':
                return $this->generateRSASignature($input, $key, 'sha512');

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

    private function urlSafeB64Encode($data)
    {
        $b64 = base64_encode($data);
        $b64 = str_replace(array('+', '/', '\r', '\n', '='),
                array('-', '_'),
                $b64);
        return $b64;
    }

    private function urlSafeB64Decode($b64)
    {
        $b64 = str_replace(array('-', '_'),
                array('+', '/'),
                $b64);
        return base64_decode($b64);
    }
}
