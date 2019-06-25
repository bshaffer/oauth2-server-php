<?php
/**
* Introspection
References:
https://datatracker.ietf.org/doc/rfc7662/

Posted parameters :

token 
REQUIRED. : (TODO :déterminer les types acceptés : JWT et ???)
token_type_hint : 
OPTIONAL. not implemented.
ip :
OPTIONAL. IP of client issuing the token to be verified. (TODO)
audience :
OPTIONAL. If token has an audience claim it will be checked against this one.

Authorization of caller :

According to rfc7662 Section 2.1., "the endpoint MUST require some form of authorization to access this endpoint".
( What we could have done to comply with this specification :
This implementation is waiting for a bearer access token issued for a registered (not public) client.
Where this access token is coming from is depending upon the service. 
It may have been obtained from the server by the caller as a client application.
Or, if the caller is a resource server queried by a client application, it may have been passed to the caller by the application.)

We submit to the reader's sagacity the following observations:

- The purpose of this autorisation is "To prevent token scanning attacks". 
This kind of attacks are usually mitigated at the firewall level in relation with the service. 
For instance, with Apache, we could set a HTTP Basic authentication at the directory level. 
Then, on a WHM/cPanel managed server, we could use CSF/LFD to block repetitive login failure. 
We could also configure a particular Apache Modsec rule for that purpose. 

- Requiring the resource server to authenticate itself makes the asumption that the server appartains to the corporate realm.
It is true in most cases, but we may expect foreign RS be able to check JWT.

   


Introspection response :


Author :
Bertrand Degoy https://oa.dnc.global
Credits :
bschaffer https://github.com/bshaffer/oauth2-server-php

Licence : GPL v3.0
Copyright (c) 2019 - DnC
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
    public function __construct(TokenTypeInterface $tokenType, AccessTokenInterface $tokenStorage, PublicKeyInterface $publicKeyStorage, $config = array(), ScopeInterface $scopeUtil = null)
    {
        //DebugBreak("435347910947900005@127.0.0.1;d=1");  //DEBUG

        parent::__construct($tokenType, $tokenStorage, $config, $scopeUtil);

        $this->publicKeyStorage = $publicKeyStorage;

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
        //DebugBreak("435347910947900005@127.0.0.1;d=1");  //DEBUG

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

        // Check the audience if required to match
        $audience = $request->request('audience', $request->query('audience'));
        if ( isset($jwt['aud']) && !is_null($audience) ) {  
            if ( $jwt['aud'] != $audience )  {
                $response->setError(400, 'invalid_grant', "Invalid audience (aud)");

                return null;
            }
        }
        
        //TODO: Check the IP if required to match

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
