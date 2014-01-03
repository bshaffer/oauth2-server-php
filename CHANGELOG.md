CHANGELOG for 1.x
=================

This changelog references the relevant changes (bug and security fixes) done
in 1.x minor versions.

To get the diff for a specific change, go to https://github.com/bshaffer/oauth2-server-php/commit/XXX where XXX is the change hash
To get the diff between two versions, go to https://github.com/bshaffer/oauth2-server-php/compare/v1.0...v1.1

* 1.2 (2014-01-03)

  PR: https://github.com/bshaffer/oauth2-server-php/pull/288

  * bug #285 changed response header from 200 to 401 when empty token received
  * bug #286 adds documentation and links to spec for not including error messages when no token is supplied
  * bug #280 ensures PHP warnings do not get thrown as a result of an invalid argument to $jwt->decode()
  * bug #279 predis wrong number of arguments
  * bug #277 Securing JS WebApp client secret w/ password grant type

* 1.1 (2013-12-17)

  PR: https://github.com/bshaffer/oauth2-server-php/pull/276

  * bug #278 adds refresh token configuration to Server class
  * bug #274 Supplying a null client_id and client_secret grants API access
  * bug #244 [MongoStorage] More detailed implementation info
  * bug #268 Implement jti for JWT Bearer tokens to prevent replay attacks.
  * bug #266 Removing unused argument to getAccessTokenData
  * bug #247 Make Bearer token type consistent
  * bug #253 Fixing CryptoToken refresh token lifetime
  * bug #246 refactors public key logic to be more intuitive
  * bug #245 adds support for JSON crypto tokens
  * bug #230 Remove unused columns in oauth_clients
  * bug #215 makes Redis Scope Storage obey the same paradigm as PDO
  * bug #228 removes scope group
  * bug #227 squelches open basedir restriction error
  * bug #223 Updated docblocks for RefreshTokenInterface.php
  * bug #224 Adds protected properties
  * bug #217 Implement ScopeInterface for PDO, Redis

* 1.0 (2013-08-12)

  * bug #203 Add redirect\_status_code config param for AuthorizeController
  * bug #205 ensures unnecessary ? is not set when  ** bug
  * bug #204 Fixed call to LogicException
  * bug #202 Add explode to checkRestrictedGrant in PDO Storage
  * bug #197 adds support for 'false' default scope  ** bug
  * bug #192 reference errors and adds tests
  * bug #194 makes some appropriate properties  ** bug
  * bug #191 passes config to HttpBasic
  * bug #190 validates client credentials before  ** bug
  * bug #171 Fix wrong redirect following authorization step
  * bug #187 client_id is now passed to getDefaultScope().
  * bug #176 Require refresh_token in getRefreshToken response
  * bug #174 make user\_id not required for refresh_token grant
  * bug #173 Duplication in JwtBearer Grant
  * bug #168 user\_id not required for authorization_code grant
  * bug #133 hardens default security for user object
  * bug #163 allows redirect\_uri on authorization_code to be NULL in docs example
  * bug #162 adds getToken on ResourceController for convenience
  * bug #161 fixes fatal error
  * bug #163 Invalid redirect_uri handling
  * bug #156 user\_id in OAuth2\_Storage_AuthorizationCodeInterface::getAuthorizationCode() response
  * bug #157 Fix for extending access and refresh tokens
  * bug #154 ResponseInterface: getParameter method is used in the library but not defined in the interface
  * bug #148 Add more detail to examples in Readme.md
