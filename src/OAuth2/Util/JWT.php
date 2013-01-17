<?php
/**
 * @link https://github.com/F21/jwt
 * @author F21
 */

class OAuth2_Util_JWT
{
    public function encode($payload, $key, $algo = 'HS256')
    {
        $header = array('typ' => 'JWT', 'alg' => $algo);

        $segments = array(
            OAuth2_Util_JWT::urlsafeB64Encode(json_encode($header)),
            OAuth2_Util_JWT::urlsafeB64Encode(json_encode($payload))
        );

        $signing_input = implode('.', $segments);


        $signature = OAuth2_Util_JWT::sign($signing_input, $key, $algo);
        $segments[] = OAuth2_Util_JWT::urlsafeB64Encode($signature);

        return implode('.', $segments);
    }

    public function decode($jwt, $key = null, $verify = true)
    {
        $tks = explode('.', $jwt);

        if (count($tks) != 3) {
            throw new Exception('Wrong number of segments');
        }

        list($headb64, $payloadb64, $cryptob64) = $tks;

        if (null === ($header = json_decode(OAuth2_Util_JWT::urlsafeB64Decode($headb64)))){
            throw new Exception('Invalid segment encoding');
        }

        if (null === $payload = json_decode(OAuth2_Util_JWT::urlsafeB64Decode($payloadb64))){
            throw new Exception('Invalid segment encoding');
        }

        $sig = OAuth2_Util_JWT::urlsafeB64Decode($cryptob64);

        if ($verify) {
            if (empty($header->alg)) {
                throw new DomainException('Empty algorithm');
            }

            if (!OAuth2_Util_JWT::verifySignature($sig, "$headb64.$payloadb64", $key, $header->alg)) {
                throw new UnexpectedValueException('Signature verification failed');
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
                return OAuth2_Util_JWT::sign($input, $key, $algo) === $signature;

            case 'RS256':
                return (boolean)openssl_verify($input, $signature, $key, OPENSSL_ALGO_SHA256);
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
                if (!openssl_sign($input, $signature, $key, OPENSSL_ALGO_SHA256)) {
                     throw new Exception("Unable to sign data.");
                }

                return $signature;

            default:
                throw new Exception("Unsupported or invalid signing algorithm.");
        }
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
