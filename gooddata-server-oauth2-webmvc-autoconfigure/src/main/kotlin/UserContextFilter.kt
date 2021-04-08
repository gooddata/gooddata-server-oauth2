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
package com.gooddata.oauth2.server.servlet

import com.gooddata.oauth2.server.common.AuthenticationStoreClient
import com.gooddata.oauth2.server.common.Organization
import com.gooddata.oauth2.server.common.User
import com.gooddata.oauth2.server.common.UserContextAuthenticationToken
import com.gooddata.oauth2.server.common.getUserContextForAuthenticationToken
import kotlinx.coroutines.runBlocking
import mu.KotlinLogging
import org.slf4j.event.Level
import org.springframework.http.HttpStatus
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.authentication.logout.LogoutHandler
import org.springframework.web.server.ResponseStatusException
import javax.servlet.Filter
import javax.servlet.FilterChain
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpFilter
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * [Filter] that takes authentication details from [SecurityContextHolder], creates user context and
 * stores it using [UserContextHolder].
 *
 * There are multiple scenarios how usr context is created. If [SecurityContext] contains
 * [UserContextAuthenticationToken] it is simply extracted and user context is created according to its content.
 *
 * In case [OAuth2AuthenticationToken] is used `UserContextFilter` retrieves [Organization] based on request's
 * hostname and [User] that corresponds to `SUB` attribute from ID token. If the [User] cannot be found the current
 * session is terminated and new authentication flow is triggered.
 *
 * `UserContextFilter` also handles global logout from all user sessions. Request's [OAuth2AuthenticationToken] is
 * compared to stored last global logout timestamp and if the token has been issued before stored date
 * current session is terminated, logout is trigger and new authentication initialization is initiated.
 */
class UserContextFilter(
    private val client: AuthenticationStoreClient,
    private val authenticationEntryPoint: AuthenticationEntryPoint,
    private val logoutHandler: LogoutHandler,
    private val userContextHolder: UserContextHolder,
) : HttpFilter() {

    private val logger = KotlinLogging.logger {}

    override fun doFilter(request: HttpServletRequest?, response: HttpServletResponse?, chain: FilterChain) {
        val authOption =
            Option(Level.DEBUG, { "Security context is not set, probably accessing unauthenticated resource" }) {
                SecurityContextHolder.getContext()
            }.map(Level.WARN, { "Security cannot be retrieved" }) {
                it.authentication
            }

        when (authOption) {
            is Option.Present -> when (val auth = authOption.value) {
                is OAuth2AuthenticationToken -> processAuthenticationToken(auth, request, response, chain)
                is UserContextAuthenticationToken -> withUserContext(auth.organization, auth.user, null) {
                    chain.doFilter(request, response)
                }
                else -> logAndContinue(request, response, chain, Level.WARN) {
                    "Security context contains unexpected authentication ${auth::class}"
                }
            }
            is Option.Empty -> logAndContinue(request, response, chain, authOption.logLevel, authOption.message)
        }
    }

    private fun processAuthenticationToken(
        auth: OAuth2AuthenticationToken,
        request: HttpServletRequest?,
        response: HttpServletResponse?,
        chain: FilterChain,
    ) {
        val (organization, user, restartAuthentication) = runBlocking {
            getUserContextForAuthenticationToken(client, auth)
        }

        if (user == null) {
            logger.info { "Session was logged out" }
            logoutHandler.logout(request, response, auth)
            if (restartAuthentication) {
                authenticationEntryPoint.commence(request, response, null)
            } else throw ResponseStatusException(HttpStatus.NOT_FOUND, "User is not registered")
        } else {
            withUserContext(organization, user, auth.name) {
                chain.doFilter(request, response)
            }
        }
    }

    private fun <T> withUserContext(
        organization: Organization,
        user: User,
        name: String?,
        block: () -> T,
    ) {
        userContextHolder.setContext(organization.id, user.id, name)
        block()
        userContextHolder.clearContext()
    }

    private fun logAndContinue(
        request: ServletRequest?,
        response: ServletResponse?,
        chain: FilterChain,
        logLevel: Level,
        message: () -> String,
    ) {
        when (logLevel) {
            Level.ERROR -> logger.error(message)
            Level.WARN -> logger.warn(message)
            Level.INFO -> logger.info(message)
            Level.DEBUG -> logger.debug(message)
            Level.TRACE -> logger.trace(message)
        }
        chain.doFilter(request, response)
    }

    sealed class Option<T> {

        @Suppress("UNCHECKED_CAST")
        fun <U> map(
            logLevel: Level,
            message: () -> String,
            mapper: (T) -> U?,
        ): Option<U> = when (this) {
            is Present -> Option(logLevel, message) {
                mapper(this.value)
            }
            is Empty -> this as Empty<U>
        }

        companion object {
            operator fun <T> invoke(
                logLevel: Level,
                message: () -> String,
                block: () -> T?,
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
