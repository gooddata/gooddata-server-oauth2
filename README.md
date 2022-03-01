# GoodData Server OAuth2 Starter

The _GoodData Server OAuth2 Starter_ is an extension to [Spring Security](https://github.com/spring-projects/spring-security)
library that adds support for storing OAuth2 related session data to HTTP only cookies.

Library is forked from [https://github.com/spring-projects/spring-security](https://github.com/spring-projects/spring-security)
to be able to reuse some internal classes and logic and stripped down to the minimum that is needed for the implementation.

## Usage in projects

### Configure Spring Boot Project

**Add project dependency:**
For WebFlux:
```
implementation('com.gooddata.oauth2.server:gooddata-server-oauth2-webflux-starter')
```

For WebMVC:
```
implementation('com.gooddata.oauth2.server:gooddata-server-oauth2-webmvc-starter')
```

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
    * redirects to `/oauth2/authorization/{providerId}`
* **/oauth2/authorization/{providerId}**
    * initiates OAuth2 authorization flow and redirects to OIDC provider
    * sets `SPRING_SEC_OAUTH2_AUTHZ_RQ`
    * redirects to OIDC with `/login/oauth2/code/{providerId}` callback URI
* **/login/oauth2/code/{providerId}**
    * OAuth2 callback URI, receives information from OIDC provider and stores them
    * sets `SPRING_SEC_OAUTH2_AUTHZ_CLIENT` and `SPRING_SEC_SECURITY_CONTEXT`
    * redirects to `REDIRECT_URI`
    * clears `SPRING_SEC_OAUTH2_AUTHZ_RQ` and `REDIRECT_URI`
* **/logout**
    * clears `SPRING_SEC_OAUTH2_AUTHZ_CLIENT`, `SPRING_SEC_SECURITY_CONTEXT` - i.e. OAuth2 tokens
* **/appLogin**
    * resource that handles unauthenticated requests and redirects authenticated to `redirectTo` query parameter

### Cross-origin resource sharing (CORS)

Settings can be specified for whole application and per-organization.

* Global - put `com.gooddata.oauth2.server.common.CorsConfigurations` bean to the application context
* per-organization - update `com.gooddata.oauth2.server.common.Organization.allowedOrigins` with you allowed origins.
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

## Updating dependencies

When updating project dependencies it is important to also update existing [attribution file](NOTICE.txt).
To request new attribution file follow the guide described on Confluence _Licencing Compliance Review Process_ under section _Procedure / Standard flow_.
