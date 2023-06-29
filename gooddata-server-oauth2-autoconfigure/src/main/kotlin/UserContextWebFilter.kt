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
package com.gooddata.oauth2.server

import mu.KotlinLogging
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono

/**
 * [WebFilter] that creates user context and stores it to coroutine/reactor context.
 *
 * There are multiple scenarios how user context is created. If [SecurityContext] contains
 * [UserContextAuthenticationToken] the [UserContextAuthenticationProcessor] simply extracts the context and user
 * context is created according to its content.
 *
 * In case [OAuth2AuthenticationToken] is used the [OidcAuthenticationProcessor] retrieves [Organization] via
 * `UserContextWebFilter` based on request's hostname and [User] that corresponds to `SUB` attribute from ID token.
 * If the [User] cannot be found the current session is terminated and new authentication flow is triggered.
 *
 * [OidcAuthenticationProcessor] also handles global logout from all user sessions. Request's
 * [OAuth2AuthenticationToken] is compared to stored last global logout timestamp and if the token has been issued
 * before stored date current session is terminated, logout is trigger and new authentication initialization is
 * initiated.
 *
 * Similarly in case [JwtAuthenticationToken] is used the [JwtAuthenticationProcessor] retrieves [Organization] by
 * request uri host. And authenticates the user based on `Jwks` configured for the given organization.
 */
class UserContextWebFilter(
    private val oidcAuthenticationProcessor: OidcAuthenticationProcessor,
    private val jwtAuthenticationProcessor: JwtAuthenticationProcessor,
    private val userContextAuthenticationProcessor: UserContextAuthenticationProcessor
) : WebFilter {

    private val logger = KotlinLogging.logger {}

    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> =
        ReactiveSecurityContextHolder.getContext()
            .switchIfEmpty(Mono.just(SecurityContextImpl(UnauthenticatedResourceAuthentication)))
            .flatMap { securityContext ->
                when (val authentication = securityContext.authentication) {
                    UnauthenticatedResourceAuthentication -> {
                        logger.debug { "Security context is not set, probably accessing unauthenticated resource" }
                        chain.filter(exchange)
                    }

                    null -> {
                        logger.warn { "Security cannot be retrieved" }
                        chain.filter(exchange)
                    }

                    else -> authentication.process(exchange, chain)
                }
            }

    private fun Authentication.process(
        exchange: ServerWebExchange,
        chain: WebFilterChain,
    ): Mono<Void> = when (this) {
        is OAuth2AuthenticationToken -> oidcAuthenticationProcessor.authenticate(this, exchange, chain)
        is JwtAuthenticationToken -> jwtAuthenticationProcessor.authenticate(this, exchange, chain)
        is UserContextAuthenticationToken -> userContextAuthenticationProcessor.authenticate(this, exchange, chain)
        else -> {
            logger.warn { "Security context contains unexpected authentication ${this::class}" }
            chain.filter(exchange)
        }
    }

    /**
     * A helper [Authentication] type for representing the empty authentication of unauthenticated resources.
     *
     * This allows us to handle all cases (unauthenticated resource, missing authentication in authenticated resource
     * and proper authentication in authenticated resource) together.
     */
    private object UnauthenticatedResourceAuthentication : AbstractAuthenticationToken(emptyList()) {
        override fun getCredentials() = null
        override fun getPrincipal() = null
    }
}
