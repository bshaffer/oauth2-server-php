<?php

namespace OAuth2\ClientAssertionType;

use OAuth2\ResponseException;
use OAuth2\Storage\ClientCredentialsInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Validate a client via Http Basic authentication
 *
 * @author    Brent Shaffer <bshafs at gmail dot com>
 */
class HttpBasic implements ClientAssertionTypeInterface
{
    private $clientData;

    protected $storage;
    protected $config;

    /**
     * @param OAuth2\Storage\ClientCredentialsInterface $clientStorage REQUIRED Storage class for retrieving client credentials information
     * @param array                                     $config        OPTIONAL Configuration options for the server
     *                                                                 <code>
     *                                                                 $config = array(
     *                                                                 'allow_credentials_in_request_body' => true, // whether to look for credentials in the POST body in addition to the Authorize HTTP Header
     *                                                                 'allow_public_clients'  => true              // if true, "public clients" (clients without a secret) may be authenticated
     *                                                                 );
     *                                                                 </code>
     */
    public function __construct(ClientCredentialsInterface $storage, array $config = array())
    {
        $this->storage = $storage;
        $this->config = array_merge(array(
            'allow_credentials_in_request_body' => true,
            'allow_public_clients' => true,
        ), $config);
    }

    public function validateRequest(RequestInterface $request, &$errors = null)
    {
        if (!$clientData = $this->getClientCredentials($request, $errors)) {
            return false;
        }

        if (!isset($clientData['client_id'])) {
            throw new \LogicException('the clientData array must have "client_id" set');
        }

        if (!isset($clientData['client_secret']) || $clientData['client_secret'] == '') {
            if (!$this->config['allow_public_clients']) {
                $errors = array(
                    'error' => 'invalid_client',
                    'description' => 'client credentials are required'
                );

                return false;
            }

            if (!$this->storage->isPublicClient($clientData['client_id'])) {
                $errors = array(
                    'error' => 'invalid_client',
                    'description' => 'This client is invalid or must authenticate using a client secret'
                );

                return false;
            }
        } elseif ($this->storage->checkClientCredentials($clientData['client_id'], $clientData['client_secret']) === false) {
            $errors = array(
                'error' => 'invalid_client',
                'description' => 'The client credentials are invalid'
            );

            return false;
        }

        $this->clientData = $clientData;

        return true;
    }

    public function getClientId()
    {
        return $this->clientData['client_id'];
    }

    /**
     * Internal function used to get the client credentials from HTTP basic
     * auth or POST data.
     *
     * According to the spec (draft 20), the client_id can be provided in
     * the Basic Authorization header (recommended) or via GET/POST.
     *
     * @return
     * A list containing the client identifier and password, for example
     * @code
     * return array(
     *     "client_id"     => CLIENT_ID,        // REQUIRED the client id
     *     "client_secret" => CLIENT_SECRET,    // OPTIONAL the client secret (may be omitted for public clients)
     * );
     * @endcode
     *
     * @see http://tools.ietf.org/html/rfc6749#section-2.3.1
     *
     * @ingroup oauth2_section_2
     */
    public function getClientCredentials(RequestInterface $request, &$errors = null)
    {
        if (
            ($clientId = $request->getHeaderLine('PHP_AUTH_USER'))
            && ($clientSecret = $request->getHeaderLine('PHP_AUTH_PW'))
        ) {
            return array(
                'client_id' => $clientId,
                'client_secret' => $clientSecret
            );
        }

        if ($authorizationHeader = $request->getServerParams()["HTTP_AUTHORIZATION"]) {
            $exploded = explode(':', base64_decode(substr($authorizationHeader, 6)));
            if (count($exploded) != 2) {
              return null;
            }

            $result = [];
            list($result['client_id'], $result['client_secret']) = $exploded;
            return $result;

        }

        if ($this->config['allow_credentials_in_request_body']) {
            $body = json_decode((string) $request->getBody(), true);
            // Using POST for HttpBasic authorization is not recommended, but is supported by specification
            if (!empty($body['client_id'])) {
                /**
                 * client_secret can be null if the client's password is an empty string
                 * @see http://tools.ietf.org/html/rfc6749#section-2.3.1
                 */

                return array(
                    'client_id' => $body['client_id'],
                    'client_secret' => isset($body['client_secret']) ? $body['client_secret'] : '',
                );
            }
        }

        $message = $this->config['allow_credentials_in_request_body'] ? ' or body' : '';

        $errors = array(
            'error' => 'invalid_client',
            'description' => 'Client credentials were not found in the headers' . $message,
        );

        return null;
    }
}
