/*
 * Copyright 2023 GoodData Corporation
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

import java.time.Instant
import mu.KotlinLogging
import org.springframework.http.HttpStatus
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.web.server.ServerAuthenticationEntryPoint
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler
import org.springframework.web.server.ResponseStatusException
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono

/**
 * If `SecurityContext` contains [OAuth2AuthenticationToken] the [OidcAuthenticationProcessor] handles the
 * authentication by retrieving [Organization] via `UserContextWebFilter` based on request's hostname and [User]
 * that corresponds to `SUB` attribute (or [Organization.oauthSubjectIdClaim]) from ID token.
 * If the [User] cannot be found the current session is terminated and new authentication flow is triggered.
 *
 * [OidcAuthenticationProcessor] also handles global logout from all user sessions. Request's
 * [OAuth2AuthenticationToken] is compared to stored last global logout timestamp and if the token has been issued
 * before stored date current session is terminated, logout is trigger and new authentication initialization is
 * initiated.
 */
class OidcAuthenticationProcessor(
    private val client: AuthenticationStoreClient,
    private val authenticationEntryPoint: ServerAuthenticationEntryPoint,
    private val serverLogoutHandler: ServerLogoutHandler,
    private val reactorUserContextProvider: ReactorUserContextProvider,
) : AuthenticationProcessor<OAuth2AuthenticationToken>(reactorUserContextProvider) {

    private val logger = KotlinLogging.logger {}

    override fun authenticate(
        authenticationToken: OAuth2AuthenticationToken,
        exchange: ServerWebExchange,
        chain: WebFilterChain,
    ): Mono<Void> =
        getUserContextForAuthenticationToken(authenticationToken).flatMap { userContext ->
            if (userContext.user == null) {
                logger.info { "Session was logged out" }
                serverLogoutHandler.logout(WebFilterExchange(exchange, chain), authenticationToken).then(
                    if (userContext.restartAuthentication) {
                        authenticationEntryPoint.commence(exchange, null)
                    } else {
                        Mono.error(ResponseStatusException(HttpStatus.NOT_FOUND, "User is not registered"))
                    }
                )
            } else {
                withUserContext(userContext.organization, userContext.user, authenticationToken.name) {
                    chain.filter(exchange)
                }
            }
        }

    /**
     * Takes provided [OAuth2AuthenticationToken] and tries to retrieve [Organization] and [User] that correspond to it.
     * Request's [OAuth2AuthenticationToken] is compared to stored last global logout timestamp and if the token
     * has been issued before stored date `null` user is returned and flag indicating that authentication flow is to be
     * restarted.
     *
     * @param authenticationStoreClient authentication client
     * @param authenticationToken OAuth2 authentication token
     * @return user context
     *
     */
    private fun getUserContextForAuthenticationToken(
        authenticationToken: OAuth2AuthenticationToken
    ): Mono<UserContext> {
        return getOrganizationFromContext().flatMap { organization ->
            client.getUserByAuthenticationId(
                organization.id,
                authenticationToken.getClaim(organization.oauthSubjectIdClaim)
            ).flatMap { user ->
                val tokenIssuedAtTime = authenticationToken.principal.attributes[IdTokenClaimNames.IAT] as Instant
                val lastLogoutAllTimestamp = user.lastLogoutAllTimestamp
                val isValid = lastLogoutAllTimestamp == null || tokenIssuedAtTime.isAfter(lastLogoutAllTimestamp)
                val userContext = if (isValid) {
                    UserContext(organization, user, restartAuthentication = false)
                } else {
                    UserContext(organization, user = null, restartAuthentication = true)
                }
                Mono.just(userContext)
            }.switchIfEmpty(
                Mono.just(
                    UserContext(organization, user = null, restartAuthentication = false)
                )
            )
        }
    }
}
