/*
 * Copyright 2021 GoodData Corporation
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

typealias RestartAuthentication = Boolean

/**
 * Builds [ClientRegistration] from [Organization] retrieved from [AuthenticationStoreClient].
 *
 * @param registrationId registration ID to be used
 * @param organization organization object retrieved from [AuthenticationStoreClient]
 */
fun buildClientRegistration(
    registrationId: String,
    organization: Organization,
    properties: HostBasedClientRegistrationRepositoryProperties,
): ClientRegistration = (
    organization.oauthIssuerLocation?.let {
        ClientRegistrations
            .fromIssuerLocation(it)
            .registrationId(registrationId)
    } ?: ClientRegistration
        .withRegistrationId(registrationId)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .authorizationUri("${properties.remoteAddress}/dex/auth")
        .tokenUri("${properties.localAddress}/dex/token")
        .userInfoUri("${properties.localAddress}/dex/userinfo")
        .userInfoAuthenticationMethod(AuthenticationMethod("header"))
        .jwkSetUri("${properties.localAddress}/dex/keys")
    )
    .clientId(organization.oauthClientId)
    .clientSecret(organization.oauthClientSecret)
    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
    .scope("openid", "profile")
    .userNameAttributeName("name")
    .build()

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
 * In case there is no [User] to be found `null` user is returned as well.
 *
 * @param client authentication client
 * @param auth OAuth2 authentication token
 * @return organization and user unless global logout has been triggered no user has been retrieved.
 * Flag indicating whether authentication flow should be restarted is returned as well.
 */
suspend fun getUserContextForAuthenticationToken(
    client: AuthenticationStoreClient,
    auth: OAuth2AuthenticationToken,
): Triple<Organization, User?, RestartAuthentication> {
    val organization = client.getOrganizationByHostname(auth.authorizedClientRegistrationId)
    val user = client.getUserByAuthenticationId(
        organization.id,
        auth.principal.attributes[IdTokenClaimNames.SUB] as String
    )?.let {
        val tokenIssuedAtTime = auth.principal.attributes[IdTokenClaimNames.IAT] as Instant
        val lastLogoutAllTimestamp = it.lastLogoutAllTimestamp
        val isValid = lastLogoutAllTimestamp == null || tokenIssuedAtTime.isAfter(lastLogoutAllTimestamp)
        if (isValid) Pair(it, false) else Pair(null, true)
    } ?: Pair(null, false)
    return Triple(organization, user.first, user.second)
}
