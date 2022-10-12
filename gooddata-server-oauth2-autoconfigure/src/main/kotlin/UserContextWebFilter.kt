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

import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.reactor.ReactorContext
import kotlinx.coroutines.reactor.mono
import kotlinx.coroutines.slf4j.MDCContext
import kotlinx.coroutines.withContext
import mu.KotlinLogging
import org.slf4j.event.Level
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

    @OptIn(ExperimentalCoroutinesApi::class)
    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> =
        mono(Dispatchers.Unconfined + CoroutineName("userContextWebFilter")) {
            val authOption = Option(Level.WARN, { "ReactorContext is not a part of coroutineContext" }) {
                coroutineContext[ReactorContext]?.context
            }.map(
                Level.DEBUG,
                { "Security context is not set, probably accessing unauthenticated resource" }
            ) { context ->
                context.getOrDefault<Mono<SecurityContext>>(SecurityContext::class.java, null)
            }.map(Level.WARN, { "Security cannot be retrieved" }) { context ->
                context.awaitOrNull()?.authentication
            }

            when (authOption) {
                is Option.Present -> when (val auth = authOption.value) {
                    is OAuth2AuthenticationToken -> processAuthenticationToken(auth, exchange, chain)
                    is UserContextAuthenticationToken -> withUserContext(auth.organization, auth.user, null) {
                        chain.filter(exchange).awaitOrNull()
                    }
                    else -> logAndContinue(exchange, chain, Level.WARN) {
                        "Security context contains unexpected authentication ${auth::class}"
                    }
                }
                is Option.Empty -> logAndContinue(exchange, chain, authOption.logLevel, authOption.message)
            }
        }

    private suspend fun processAuthenticationToken(
        auth: OAuth2AuthenticationToken,
        exchange: ServerWebExchange,
        chain: WebFilterChain,
    ): Void? {
        val userContext = getUserContextForAuthenticationToken(client, auth)

        return if (userContext.user == null) {
            logger.info { "Session was logged out" }
            serverLogoutHandler.logout(WebFilterExchange(exchange, chain), auth).awaitOrNull()
            if (userContext.restartAuthentication) {
                authenticationEntryPoint.commence(exchange, null).awaitOrNull()
            } else {
                throw ResponseStatusException(HttpStatus.NOT_FOUND, "User is not registered")
            }
        } else {
            withUserContext(userContext.organization, userContext.user!!, auth.name) {
                chain.filter(exchange).awaitOrNull()
            }
        }
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    private suspend fun <T> withUserContext(
        organization: Organization,
        user: User,
        name: String?,
        block: suspend () -> T,
    ): T {
        val reactorContext = userContextHolder.setContext(organization.id, user.id, name)
        return withContext(reactorContext + MDCContext()) {
            block()
        }
    }

    private suspend fun logAndContinue(
        exchange: ServerWebExchange,
        chain: WebFilterChain,
        logLevel: Level,
        message: () -> String,
    ): Void? {
        when (logLevel) {
            Level.ERROR -> logger.error(message)
            Level.WARN -> logger.warn(message)
            Level.INFO -> logger.info(message)
            Level.DEBUG -> logger.debug(message)
            Level.TRACE -> logger.trace(message)
        }
        return chain.filter(exchange).awaitOrNull()
    }

    sealed class Option<T> {

        @Suppress("UNCHECKED_CAST")
        suspend fun <U> map(
            logLevel: Level,
            message: () -> String,
            mapper: suspend (T) -> U?,
        ): Option<U> = when (this) {
            is Present -> Option(logLevel, message) {
                mapper(this.value)
            }
            is Empty -> this as Empty<U>
        }

        companion object {
            suspend operator fun <T> invoke(
                logLevel: Level,
                message: () -> String,
                block: suspend () -> T?,
            ): Option<T> {
                val value = block()
                return if (value != null) {
                    Present(value)
                } else {
                    Empty(logLevel, message)
                }
            }
        }

        data class Present<T>(val value: T) : Option<T>()

        data class Empty<T>(val logLevel: Level, val message: () -> String) : Option<T>()
    }
}
