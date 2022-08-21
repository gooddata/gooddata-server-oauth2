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
package com.gooddata.oauth2.server.reactive

import com.gooddata.oauth2.server.common.AuthenticationStoreClient
import com.gooddata.oauth2.server.common.Organization
import com.gooddata.oauth2.server.common.User
import com.gooddata.oauth2.server.common.UserContextAuthenticationToken
import com.gooddata.oauth2.server.common.getUserContextForAuthenticationToken
import kotlinx.coroutines.reactor.mono
import mu.KotlinLogging
import org.springframework.http.HttpStatus
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.web.server.ServerAuthenticationEntryPoint
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler
import org.springframework.web.server.ResponseStatusException
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono

/**
 * [WebFilter] that creates user context and stores it to coroutine/reactor context.
 *
 * There are multiple scenarios how user context is created. If [SecurityContext] contains
 * [UserContextAuthenticationToken] it is simply extracted and user context is created according to its content.
 *
 * In case [OAuth2AuthenticationToken] is used `UserContextWebFilter` retrieves [Organization] based on request's
 * hostname and [User] that corresponds to `SUB` attribute from ID token. If the [User] cannot be found the current
 * session is terminated and new authentication flow is triggered.
 *
 * [UserContextWebFilter] also handles global logout from all user sessions. Request's [OAuth2AuthenticationToken] is
 * compared to stored last global logout timestamp and if the token has been issued before stored date
 * current session is terminated, logout is trigger and new authentication initialization is initiated.
 */
class UserContextWebFilter(
    private val client: AuthenticationStoreClient,
    private val authenticationEntryPoint: ServerAuthenticationEntryPoint,
    private val serverLogoutHandler: ServerLogoutHandler,
    private val userContextHolder: UserContextHolder<*>,
) : WebFilter {

    private val logger = KotlinLogging.logger {}

    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> =
        Mono.deferContextual { context ->
            val securityContext = context.getOrEmpty<SecurityContext>(SecurityContext::class.java)
            Mono.just(securityContext)
        }.flatMap { securityContextOption ->
            securityContextOption.map { securityContext ->
                when (val auth = securityContext.authentication) {
                    is OAuth2AuthenticationToken -> processAuthenticationToken(auth, exchange, chain)
                    is UserContextAuthenticationToken -> {
                        chain.filter(exchange).withUserContext(auth.organization.id, auth.user.id, null)
                    }

                    else -> {
                        logger.warn { "Security context contains unexpected authentication ${auth::class}" }
                        chain.filter(exchange)
                    }
                }
            }.orElseGet {
                logger.debug("Security context is not set, probably accessing unauthenticated resource")
                chain.filter(exchange)
            }
        }

    private fun processAuthenticationToken(
        auth: OAuth2AuthenticationToken,
        exchange: ServerWebExchange,
        chain: WebFilterChain,
    ): Mono<Void> =
        mono { getUserContextForAuthenticationToken(client, auth) }
            .flatMap { userContext ->
                if (userContext.user == null) {
                    logger.info { "Session was logged out" }
                    serverLogoutHandler.logout(WebFilterExchange(exchange, chain), auth)
                        .flatMap {
                            if (userContext.restartAuthentication) {
                                authenticationEntryPoint.commence(exchange, null)
                            } else {
                                Mono.error(ResponseStatusException(HttpStatus.NOT_FOUND, "User is not registered"))
                            }
                        }
                } else {
                    chain
                        .filter(exchange)
                        .withUserContext(userContext.organization.id, userContext.user!!.id, auth.name)
                }
            }

    private fun Mono<Void>.withUserContext(organizationId: String, userId: String, userName: String?): Mono<Void> =
        contextWrite { context ->
            userContextHolder.addUserContext(context, organizationId, userId, userName)
        }
}
