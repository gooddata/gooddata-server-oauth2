# GoodData Server OAuth2 Starter

The _GoodData Server OAuth2 Starter_ is an extension to [Spring Security](https://github.com/spring-projects/spring-security)
library that adds support for storing OAuth2 related session data to HTTP only cookies.

Library is forked from [https://github.com/spring-projects/spring-security](https://github.com/spring-projects/spring-security)
to be able to reuse some internal classes and logic and stripped down to the minimum that is needed for the implementation.

This Library is based on WebFlux [Spring Documentation](https://docs.spring.io/spring-framework/docs/current/reference/html/web-reactive.html)

## Usage in projects

### Configure Spring Boot Project

**Add project dependency:**
```
implementation('com.gooddata.oauth2.server:gooddata-server-oauth2-starter')
```

### Using authentication entities

The authentication implemented by this library is dependent on authentication entities stored in the persistent storage
of the resource server. For being able to fetch information from this persistent storage, the implementation should
extend [AuthenticationStoreClient](gooddata-server-oauth2-autoconfigure/src/main/kotlin/AuthenticationStoreClient.kt) interface
and use related `Organization` (see [Multiple organizations support](#multiple-organizations-support)) and `User`
entities.

## Architecture

This Spring Boot Starter defines set of beans that override default Spring Security implementations. By default,
Spring Security stores authentication-related info in memory. That could be potentially problematic as we are going to
integrate the starter to all front-facing applications, and we'd need deploy authentication in HA.

Spring Security suggests to use server-side caching into e.g. Redis, but we didn't want to add another component,
so we store session information into HTTP cookies.

### HTTP cookies

OIDC related data (access code, id token and refresh token) is stored in HTTP cookies.

* **SPRING_SEC_OAUTH2_AUTHZ_RQ**
    * information needed for initiation for OAuth2 authorization flow
* **SPRING_SEC_OAUTH2_AUTHZ_CLIENT**
    * Access token, Refresh token
* **SPRING_SEC_SECURITY_CONTEXT**
    * ID token
* **REDIRECT_URI**
    * original requested URI before authentication redirects

Relevant Spring Security POJOs are serialized to JSON, base64 encoded and stored into HTTP response cookies.
When cookie needs to be invalidated, its maxAge is set to 0.

Cookies are encrypted with Authenticated Encryption using "tink" library.
Currently, there is hardcoded keyset in `CookieSerializer`, but it is also prepared for reading keyset
from file.
Keyset can be created using 'tinkey' command line utility:
```
root@a45628275f4a:/# ./tinkey create-keyset --key-template AES256_GCM
{
    "primaryKeyId": 424076409,
    "key": [{
        "keyData": {
            "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
            "keyMaterialType": "SYMMETRIC",
            "value": "GiA7h+rZAv2kOd+Xiy5TSyKXKGCxfuAEQDVHVBDuZjIKdQ=="
        },
        "outputPrefixType": "TINK",
        "keyId": 424076409,
        "status": "ENABLED"
    }]
}
```

### HTTP endpoints

* **any resource** behind authentication
    * sets `REDIRECT_URI`
    * redirects to `/oauth2/authorization/{registrationId}`
* **/oauth2/authorization/{registrationId}**
    * initiates OAuth2 authorization flow and redirects to OIDC provider
    * sets `SPRING_SEC_OAUTH2_AUTHZ_RQ`
    * redirects to OIDC with `/login/oauth2/code/{registrationId}` (or `/login/oauth2/code/{issuerId}`) callback URI
* **/login/oauth2/code/{registrationId/issuerId}**
    * OAuth2 callback URI, receives information from OIDC provider and stores them
    * sets `SPRING_SEC_OAUTH2_AUTHZ_CLIENT` and `SPRING_SEC_SECURITY_CONTEXT`
    * redirects to `REDIRECT_URI`
    * clears `SPRING_SEC_OAUTH2_AUTHZ_RQ` and `REDIRECT_URI`
* **/logout**
    * clears `SPRING_SEC_OAUTH2_AUTHZ_CLIENT`, `SPRING_SEC_SECURITY_CONTEXT` - i.e. OAuth2 tokens
* **/appLogin**
    * resource that handles unauthenticated requests and redirects authenticated to `redirectTo` query parameter

### Multiple organizations support

For alignment with GoodData products, the library supports multiple organizations which can use different OIDC providers
(providers). Therefore, for the simplicity, individual organizations has own
[ClientRegistrations](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/oauth2/client/registration/ClientRegistration.html)
where the `registrationId` is in fact the `hostname` of the corresponding organization.
See also [Using authentication entities](#using-authentication-entities) for additional info.

There's a possibility to share the same OIDC provider between multiple organizations and use the single static callback
relative URI for the authentication response from the OIDC provider (see [HTTP endpoints](#http-endpoints)). This can be
achieved by using hardcoded value in the `issuerId` property for each such organization (see the `Organization` entity
in [AuthenticationStoreClient](gooddata-server-oauth2-autoconfigure/src/main/kotlin/AuthenticationStoreClient.kt)). Such
feature then can help to simplify the OIDC provider configuration (defining single callback URL vs. multiple ones).

#### Example
We have 2 organizations:
* "Org #1" with the domain `org1.resource-server.com`
* "Org #2" with the domain `org2.resource-server.com`

This means that we have 2 client registrations:
* Registration with ID `org1.resource-server.com`
* Registration with ID `org2.resource-server.com`

Default callback URLs will be:
* For "Org #1": `https://org1.resource-server.com/login/oauth2/code/org1.resource-server.com`
* For "Org #2": `https://org2.resource-server.com/login/oauth2/code/org2.resource-server.com`

In the case we want set "shared" callback URL for a single MyOIDC provider:
* For both organizations, set the `issuerId` field to some value (e.g. `myoidc`). Callback URLs will be:
  * For "Org #1": `https://org1.resource-server.com/login/oauth2/code/myoidc`
  * For "Org #2": `https://org2.resource-server.com/login/oauth2/code/myoidc`
* We set callback URL in OIDC to `https://*.resource-server.com/login/oauth2/code/myoidc` (NOTE: the provider *must*
support wildcards like `*`). This will match callback URLs for both organizations from above.

### Cross-origin resource sharing (CORS)

Settings can be specified for whole application and per-organization.

* Global - put `com.gooddata.oauth2.server.CorsConfigurations` bean to the application context
* per-organization - update `com.gooddata.oauth2.server.Organization.allowedOrigins` with you allowed origins.
  Format is `http[s]://host[:port]`.

At first global settings are tried and if none match then per-organization is tried.

## Configuration Properties

* **spring.security.oauth2.client.cookies.duration**
    * Cookie validity.
    * defaults to 7 days
* **spring.security.oauth2.client.cookies.same-site**
    * SameSite attribute used for created cookies.
    * possible options Lax, Strict and None
    * defaults to Lax
* **spring.security.oauth2.client.cookies.key-set-cache-duration**
    * Max lifetime of key set cache used for cookie encryption.
    * defaults to 10 minutes
* **spring.security.oauth2.client.repository.remote-address**
    * Address of the built-in OIDC provider that is accessible from user's web browser.
    * defaults to http://localhost:3000
* **spring.security.oauth2.client.repository.local-address**
    * Address of the built-in OIDC provider that is accessible from services that use this starter.
    * defaults to http://dex:5556
* **spring.security.oauth2.client.applogin.allow-redirect**
    * Defines which hostnames are allowed to be used in `redirectTo` param on `/appLogin` resource. When empty value is used it means that only relative URIs are allowed in `redirectTo`. If hostname is set to some schema+host+port (e.g. http://localhost:3000) then request can be redirected there.
    * defaults to empty value
* **spring.security.oauth2.client.cache.jwkMaxSize**
    * Max size of JWK cache
    * defaults to 10000
* **spring.security.oauth2.client.cache.jwkExpireAfterWriteMinutes**
    * Time in minutes after write after which is value expired in JWK cache
    * defaults to 60 minutes
* **spring.security.oauth2.client.cache.clientRegistrationMaxSize**
    * Max size of client registration cache
    * defaults to 10000
* **spring.security.oauth2.client.cache.clientRegistrationExpireAfterWriteMinutes**
    * Time in minutes after write after which is value expired in client registration cache
    * defaults to 60 minutes
* **spring.security.oauth2.client.http.readTimeoutMillis**
    * A timeout for receiving some response to a request to Oauth2 authorization server. (in milliseconds)
    * defaults to 5000
* **spring.security.oauth2.client.http.connectTimeoutMillis**
    * A timeout for establishing a TCP connection with Oauth2 authorization server. (in milliseconds)
    * defaults to 30000

## Updating dependencies

When updating project dependencies it is important to also update existing [attribution file](NOTICE.txt).
To request new attribution file follow the guide described on Confluence _Licencing Compliance Review Process_ under section _Procedure / Standard flow_.
