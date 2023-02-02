/*
 * Copyright 2022 GoodData Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.gooddata.oauth2.server

import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ClientRegistrations
import org.springframework.security.oauth2.core.AuthenticationMethod
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken
import java.time.Instant

/**
 * Constants for OAuth type authentication which are not directly available in the Spring Security.
 */
object OAuthConstants {
    /**
     * Base URL path with placeholders (`{baseUrl}`, `{action}`) for the OAuth redirect URL (`redirect_uri`).
     *
     * @see org.springframework.security.config.oauth2.client.CommonOAuth2Provider
     * @see ClientRegistration
     */
    const val REDIRECT_URL_BASE = "{baseUrl}/{action}/oauth2/code/"
}

/**
 * Builds [ClientRegistration] from [Organization] retrieved from [AuthenticationStoreClient].
 *
 * @param registrationId registration ID to be used
 * @param organization organization object retrieved from [AuthenticationStoreClient]
 * @param properties static properties for being able to configure pre-configured DEX issuer
 * @param clientRegistrationBuilderCache the cache where non-DEX client registration builders are saved
 * for improving performance
 */
fun buildClientRegistration(
    registrationId: String,
    organization: Organization,
    properties: HostBasedClientRegistrationRepositoryProperties,
    clientRegistrationBuilderCache: ClientRegistrationBuilderCache,
): ClientRegistration =
    if (organization.oauthIssuerLocation != null) {
        clientRegistrationBuilderCache.get(organization.oauthIssuerLocation) {
            ClientRegistrations.fromIssuerLocation(organization.oauthIssuerLocation)
        }
            .registrationId(registrationId)
            .withRedirectUri(organization.oauthIssuerId)
    } else {
        ClientRegistration
            .withRegistrationId(registrationId)
            .withDexConfig(properties)
    }.withIssuerConfig(organization).build()

/**
 * Adds the redirect URL to this receiver in the case the [oauthIssuerId] is defined, otherwise the default value
 * for this receiver is used.
 *
 * @receiver the [ClientRegistration] builder
 * @param oauthIssuerId the OAuth Issuer ID, can be `null`
 * @return updated receiver
 */
private fun ClientRegistration.Builder.withRedirectUri(oauthIssuerId: String?) = if (oauthIssuerId != null) {
    redirectUri("${OAuthConstants.REDIRECT_URL_BASE}/$oauthIssuerId")
} else this

/**
 * Adds the OIDC issuer configuration to this receiver.
 *
 * @receiver the [ClientRegistration] builder
 * @param organization the organization containing OIDC issuer configuration
 * @return this builder
 */
private fun ClientRegistration.Builder.withIssuerConfig(
    organization: Organization,
) = clientId(organization.oauthClientId)
    .clientSecret(organization.oauthClientSecret)
    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
    .scope("openid", "profile")
    .userNameAttributeName("name")

/**
 * Adds the DEX issuer static configuration to this receiver.
 *
 * @receiver the [ClientRegistration] builder
 * @param properties static properties for being able to configure pre-configured DEX issuer
 * @return this builder
 */
private fun ClientRegistration.Builder.withDexConfig(
    properties: HostBasedClientRegistrationRepositoryProperties,
) = redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
    .authorizationUri("${properties.remoteAddress}/dex/auth")
    .tokenUri("${properties.localAddress}/dex/token")
    .userInfoUri("${properties.localAddress}/dex/userinfo")
    .userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
    .jwkSetUri("${properties.localAddress}/dex/keys")

/**
 * Retrieves user and organization details from [AuthenticationStoreClient] for given Bearer token.
 *
 * @param client authentication client
 * @param hostname hostname to be queried
 * @param authentication Bearer token authentication details
 */
suspend fun userContextAuthenticationToken(
    client: AuthenticationStoreClient,
    hostname: String,
    authentication: BearerTokenAuthenticationToken,
): UserContextAuthenticationToken {
    val organization = client.getOrganizationByHostname(hostname)
    val user = client.getUserByApiToken(organization.id, authentication.token)
    return UserContextAuthenticationToken(organization, user)
}

/**
 * Takes provided [OAuth2AuthenticationToken] and tries to retrieve [Organization] and [User] that correspond to it.
 *
 * Request's [OAuth2AuthenticationToken] is compared to stored last global logout timestamp and if the token
 * has been issued before stored date `null` user is returned and flag indicating that authentication flow is to be
 * restarted.
 *
 * @param authenticationStoreClient authentication client
 * @param authenticationToken OAuth2 authentication token
 * @return user context
 *
 */
suspend fun getUserForAuthenticationToken(
    authenticationStoreClient: AuthenticationStoreClient,
    authenticationToken: OAuth2AuthenticationToken,
): UserFromTokenResult {
    val organization =
        authenticationStoreClient.getOrganizationByHostname(authenticationToken.authorizedClientRegistrationId)
    val user = authenticationStoreClient.getUserByAuthenticationId(
        organization.id,
        authenticationToken.principal.attributes[IdTokenClaimNames.SUB] as String
    )

    return when {
        user == null -> UserFromTokenResult.UserNotFound
        authenticationToken.isExpired() -> UserFromTokenResult.ExpiredToken
        !authenticationToken.isValidSession(user.lastLogoutAllTimestamp) -> UserFromTokenResult.LoggedOutUser
        else -> UserFromTokenResult.UserContext(organization, user)

    }
}

private const val MAX_CLOCK_SKEW = DefaultJWTClaimsVerifier.DEFAULT_MAX_CLOCK_SKEW_SECONDS.toLong()
private fun OAuth2AuthenticationToken.isExpired(): Boolean {
    val expiredTime = principal.attributes[IdTokenClaimNames.EXP] as Instant
    val expTimeWithClockSkew = expiredTime.plusSeconds(MAX_CLOCK_SKEW)
    return Instant.now().isAfter(expTimeWithClockSkew)
}

private fun OAuth2AuthenticationToken.isValidSession(lastLogout: Instant?): Boolean {
    val tokenIssuedAtTime = principal.attributes[IdTokenClaimNames.IAT] as Instant
    return lastLogout == null || tokenIssuedAtTime.isAfter(lastLogout)
}

/**
 * Remove illegal characters from string according to OAuth2 specification
 */
fun String.removeIllegalCharacters(): String = filter(::isLegalChar)

/**
 * Detect if character is legal according to OAuth2 specification
 */
@Suppress("MagicNumber")
private fun isLegalChar(c: Char): Boolean =
    (c.code <= 0x7f) && (c.code in 0x20..0x21 || c.code in 0x23..0x5b || c.code in 0x5d..0x7e)

sealed class UserFromTokenResult(val shouldDestroySession: Boolean) {

    object UserNotFound : UserFromTokenResult(true)
    object ExpiredToken : UserFromTokenResult(true)
    object LoggedOutUser : UserFromTokenResult(true)
    /**
     * Organization and user unless global logout has been triggered or no user has been retrieved.
     */
    data class UserContext(
        /**
         * Organization
         */
        val organization: Organization,
        /**
         * User or `null` if no [User] has been found or global logout has been triggered
         */
        val user: User,
    ) : UserFromTokenResult(false)
}


