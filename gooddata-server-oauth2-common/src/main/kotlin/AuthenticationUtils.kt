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
package com.gooddata.oauth2.server.common

import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ClientRegistrations
import org.springframework.security.oauth2.core.AuthenticationMethod
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken
import java.time.Instant

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
            ClientRegistrations
                .fromIssuerLocation(organization.oauthIssuerLocation)
        }.registrationId(registrationId)
    } else {
        ClientRegistration
            .withRegistrationId(registrationId)
            .withDexConfig(properties)
    }.withIssuerConfig(organization).build()

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
    .userInfoAuthenticationMethod(AuthenticationMethod("header"))
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
 * @param client authentication client
 * @param auth OAuth2 authentication token
 * @return user context
 *
 */
suspend fun getUserContextForAuthenticationToken(
    client: AuthenticationStoreClient,
    auth: OAuth2AuthenticationToken,
): UserContext {
    val organization = client.getOrganizationByHostname(auth.authorizedClientRegistrationId)
    return client.getUserByAuthenticationId(
        organization.id,
        auth.principal.attributes[IdTokenClaimNames.SUB] as String
    )?.let { user ->
        val tokenIssuedAtTime = auth.principal.attributes[IdTokenClaimNames.IAT] as Instant
        val lastLogoutAllTimestamp = user.lastLogoutAllTimestamp
        val isValid = lastLogoutAllTimestamp == null || tokenIssuedAtTime.isAfter(lastLogoutAllTimestamp)
        if (isValid) {
            UserContext(organization, user, restartAuthentication = false)
        } else {
            UserContext(organization, user = null, restartAuthentication = true)
        }
    } ?: UserContext(organization, user = null, restartAuthentication = false)
}

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
    val user: User?,
    /**
     * Flag indicating whether authentication flow should be restarted or not
     */
    val restartAuthentication: Boolean,
)
