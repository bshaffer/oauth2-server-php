<?php
/**
* Introspection
* 
* References: 
*   https://datatracker.ietf.org/doc/rfc7662/
* 
* Posted parameters :
* token 
*   REQUIRED. 
* token_type_hint : 
*   OPTIONAL. not implemented.
* requester_ip :
*   OPTIONAL. IP of client issuing the token to be verified.
* audience :
*   OPTIONAL. If token has an audience claim it will be checked against this one.
*
* Author :
*   Bertrand Degoy https://oa.dnc.global
* Credits :
*   bschaffer https://github.com/bshaffer/oauth2-server-php
* 
* Licence : 
*   GPL v3.0
* Copyright (c) 2019 - DnC
* 
*/

namespace OAuth2\OpenID\Controller;

use OAuth2\Scope;
use OAuth2\TokenType\TokenTypeInterface;
use OAuth2\Storage\AccessTokenInterface;
use OAuth2\Storage\PublicKeyInterface;
use OAuth2\Controller\ResourceController;
use OAuth2\ScopeInterface;
use OAuth2\Encryption\EncryptionInterface;
use OAuth2\Encryption\Jwt;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;
use OAuth2\Bearer;
use OAuth2\Storage\ClientInterface;

/**
* @see OAuth2\Controller\IntrospectControllerInterface
*/
class IntrospectController extends ResourceController implements IntrospectControllerInterface
{
    /**
    * @var PublicKeyInterface
    */
    protected $publicKeyStorage;

    /**
    * @var ClientInterface
    */
    protected $clientStorage;

    /**
    * @var EncryptionInterface
    */
    protected $encryptionUtil;

    /**
    * Constructor
    *
    * @param TokenTypeInterface   $tokenType
    * @param PublicKeyInterface   $publicKeyStorage
    * @param array                $config
    * @param ScopeInterface       $scopeUtil
    */
    public function __construct(TokenTypeInterface $tokenType, AccessTokenInterface $tokenStorage, ClientInterface $clientStorage, PublicKeyInterface $publicKeyStorage, $config = array(), ScopeInterface $scopeUtil = null)
    {

        parent::__construct($tokenType, $tokenStorage, $config, $scopeUtil);

        $this->publicKeyStorage = $publicKeyStorage;

        $this->clientStorage = $clientStorage;

        $this->encryptionUtil = new Jwt();
    }

    /**
    * Handle the introspection request.
    * Set response according to JWT validity.
    *
    * @param RequestInterface $request
    * @param ResponseInterface $response
    * @return bool true/false
    */
    public function handleIntrospectRequest(RequestInterface $request, ResponseInterface $response)
    {
        // Get and decode ID token
        $id_token = $this->tokenType->getAccessTokenParameter($request,$response);
        $jwt = $this->encryptionUtil->decode($id_token, null, false);

        // Verify the JWT
        if (!$jwt) {
            $response->setError(400, 'invalid_request', "JWT is malformed");

            return null;
        }

        // ensure these properties contain a value
        // @todo: throw malformed error for missing properties
        $jwt = array_merge(array(
            'scope' => null,
            'iss' => null,
            'sub' => null,
            'aud' => null,
            'exp' => null,
            'nbf' => null,
            'iat' => null,
            'jti' => null,
            'typ' => null,
            ), $jwt);

        if (!isset($jwt['iss'])) {
            $response->setError(400, 'invalid_grant', "Invalid issuer (iss) provided");

            return null;
        }

        if (!isset($jwt['exp'])) {
            $response->setError(400, 'invalid_grant', "Expiration (exp) time must be present");

            return null;
        }

        // is the JWT in the time limits ?
        $is_active = true;
        // Check expiration
        if (ctype_digit($jwt['exp'])) {
            if ($jwt['exp'] <= time()) {
                $is_active = false;
            }
        } else {
            $response->setError(400, 'invalid_grant', "Expiration (exp) time must be a unix time stamp");
            return null;
        }
        // Check the not before time
        if ($notBefore = $jwt['nbf']) {
            if (ctype_digit($notBefore)) {
                if ($notBefore > time()) {
                    $is_active = false;
                }
            } else {
                $response->setError(400, 'invalid_grant', "Not Before (nbf) time must be a unix time stamp");
                return null;
            }
        }

        // Check the audience if required to match.
        $audience = $request->request('audience', $request->query('audience'));
        if ( isset($jwt['aud']) && !is_null($audience) ) {  
            if ( $jwt['aud'] != $audience )  {
                $response->setError(400, 'invalid_grant', "Invalid audience (aud)");

                return null;
            }
        }

        /** Check requester's requester IP if required to match.
        * If the requester passed the IP of its own requester, we must check that this IP is in the subnet 
        * of the client application identified by 'aud'.
        * @see https://tools.ietf.org/html/rfc7662#section-2.1 
        */
        if ( !empty( $requester_ip = $request->request('requester_ip', $request->query('requester_ip')) ) ) {

            // Get client host from redirect URI
            $clientData = $this->clientStorage->getClientDetails($jwt['aud']);
            $registered_redirect_uri = $clientData['redirect_uri'];
            $hostname = parse_url($registered_redirect_uri)['host'];

            // Get array of host IPs from dns
            $client_ips = gethostbynamel($hostname); 

            // Check same subnet 
            if ( $client_ips ) {

                $subnetmask = $this->config['check_client_ip_mask'] ? $this->config['check_client_ip_mask'] : '255.255.255.255';
                $long_requester_subnet = ip2long($requester_ip) & ip2long($subnetmask);

                $Ok = false;
                foreach( $client_ips as $n => $client_ip ) {
                    $long_client_subnet = ip2long($client_ip) & ip2long($subnetmask); 
                    if ( $Ok = ($long_requester_subnet === $long_client_subnet) ) {     
                        break;
                    } 
                }

                if ( !$Ok ) {
                    // not in any subnet of client
                    $response->setError(400,'invalid_grant', 'Invalid IP');

                    return null;
                }   

            } else {
                // Error : we MUST check the IP but we can't.
                $response->setError(400,'invalid_grant', 'Hostname not resolved');

                return null;
            }

        } 


        // Check the jti (nonce)
        // @see http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-13#section-4.1.7
        if (isset($jwt['jti'])) {
            $jti = $this->storage->getJti($jwt['iss'], $jwt['sub'], $jwt['aud'], $jwt['exp'], $jwt['jti']);

            //Reject if jti is used and jwt is still valid (exp parameter has not expired).
            if ($jti && $jti['expires'] > time()) {
                $response->setError(400, 'invalid_grant', "JSON Token Identifier (jti) has already been used");

                return null;
            } else {
                $this->storage->setJti($jwt['iss'], $jwt['sub'], $jwt['aud'], $jwt['exp'], $jwt['jti']);
            }
        }

        // Get client and its public key
        $client_id  = isset($jwt['aud']) ? $jwt['aud'] : null;     // Use global ("server") public key if client not defined
        $public_key = $this->publicKeyStorage->getPublicKey($client_id);
        $algorithm  = $this->publicKeyStorage->getEncryptionAlgorithm($client_id);
        if ( !is_null($public_key) ) {
            // verify JWT signature
            if ( false === $this->encryptionUtil->decode($id_token, $public_key, array($algorithm)) ) {
                $response->setError(400, 'invalid_token', 'JWT not verified');

                return null;
            }
        } else {
            // Either we have a null client with no global key, or the client is invalid (has no key).  
            $response->setError(400, 'invalid_client', 'Invalid or undefined client');

            return null;
        }

        // @see rfc7662 section 2.2.
        $answer = array (
            'active' => $is_active,
            'iss' => $jwt['iss'],       
            'exp' => $jwt['exp'],              
        );

        if ( isset($jwt['scope']) ) {
            $answer['scope'] = $jwt['scope'];    
        }

        if ( isset($jwt['client_id']) ) {
            $answer['client_id'] = $jwt['client_id'];    
        }

        if ( isset($jwt['username']) ) {
            $answer['username'] = $jwt['username'];    
        }

        // token-type ???

        if ( isset($jwt['nbf']) ) {
            $answer['nbf'] = $jwt['nbf'];    
        }

        if ( isset($jwt['sub']) ) {
            $answer['sub'] = $jwt['sub'];
        } 

        if ( isset($jwt['aud']) ) {
            $answer['aud'] = $jwt['aud'];    
        }

        if ( isset($jwt['jti']) ) {
            $answer['jti'] = $jwt['jti'];    
        }

        $response->addParameters($answer);

    } 



}
