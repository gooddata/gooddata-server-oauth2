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

import com.gooddata.oauth2.server.common.AppLoginProperties
import com.gooddata.oauth2.server.common.AuthenticationStoreClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.reactor.mono
import mu.KotlinLogging
import org.springframework.http.HttpMethod
import org.springframework.security.web.server.DefaultServerRedirectStrategy
import org.springframework.security.web.server.util.matcher.AndServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import org.springframework.web.util.UriComponentsBuilder
import reactor.core.publisher.Mono
import java.net.URI

/**
 * [WebFilter] responsible of handling GET requests to `/appLogin?redirectTo={redirectTo}` URIs. When such URI is
 * requested filter uses `redirectTo` query param and responds with redirect to it.
 *
 * `redirectTo` URI is normalized, if relative URI is passed it is used, if absolute URI is passed it is checked
 * against allowed origin from properties.
 *
 * This [WebFilter] is in place mainly to allow JS apps to benefit from server-side OIDC authentication.
 */
class AppLoginWebFilter(
    private val properties: AppLoginProperties,
    private val authenticationStoreClient: AuthenticationStoreClient
) : WebFilter {

    private val logger = KotlinLogging.logger {}

    private val redirectStrategy = DefaultServerRedirectStrategy()

    private val matcher = AndServerWebExchangeMatcher(
        ServerWebExchangeMatchers.pathMatchers(HttpMethod.GET, APP_LOGIN_PATH),
        ServerWebExchangeMatcher { serverWebExchange ->
            mono {
                serverWebExchange
                    .redirectToOrNull()
                    ?.takeIf { redirectTo -> canRedirect(redirectTo, serverWebExchange) }
            }.flatMap { redirectTo ->
                ServerWebExchangeMatcher.MatchResult.match(mapOf(REDIRECT_TO to redirectTo.toASCIIString()))
            }.switchIfEmpty(ServerWebExchangeMatcher.MatchResult.notMatch())
        }
    )

    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> = mono(Dispatchers.Unconfined) {
        val redirectTo = matcher.matches(exchange)
            .awaitOrNull()
            ?.takeIf { it.isMatch }
            ?.let { it.variables[REDIRECT_TO] as String }

        if (redirectTo != null) {
            redirectStrategy.sendRedirect(exchange, URI.create(redirectTo))
        } else {
            chain.filter(exchange).then(Mono.empty())
        }.awaitOrNull()
    }

    @Suppress("TooGenericExceptionCaught")
    private fun ServerWebExchange.redirectToOrNull(): URI? {
        val redirectTo = this.request.queryParams[REDIRECT_TO]?.firstOrNull()
        return if (redirectTo == null) {
            logger.trace { "Query param \"$REDIRECT_TO\" not found" }
            null
        } else {
            try {
                URI.create(redirectTo).normalize()
            } catch (exception: Throwable) {
                logger.debug { "URL normalization error: $exception" }
                null
            }
        }
    }

    private suspend fun canRedirect(redirectTo: URI, serverWebExchange: ServerWebExchange): Boolean {
        val uri = redirectTo.normalizeToRedirectToPattern()
        val organizationHost = serverWebExchange.request.uri.host
        val allow =
            uri.isAllowedGlobally() || redirectTo.isLocal() || uri.isAllowedForOrganization(organizationHost)
        if (!allow) {
            logger.trace { "URI \"$uri\" can't be redirected" }
        }
        return allow
    }

    private fun URI.normalizeToRedirectToPattern() =
        UriComponentsBuilder.fromUri(this)
            .replacePath(null)
            .replaceQuery(null)
            .fragment(null)
            .build().toUri()

    private suspend fun URI.isAllowedForOrganization(organizationHost: String): Boolean {
        val allowedOrigins = authenticationStoreClient
            .getOrganizationByHostname(organizationHost)
            .allowedOrigins
            ?.map { URI(it) }

        return allowedOrigins != null && allowedOrigins.any { this == it.normalizeToRedirectToPattern() }
    }

    private fun URI.isAllowedGlobally() = this == properties.allowRedirect

    private fun URI.isLocal() = normalizeToRedirectToPattern() == EMPTY_URI && path.startsWith("/")

    companion object {
        const val APP_LOGIN_PATH = "/appLogin"
        internal const val REDIRECT_TO = "redirectTo"
        private val EMPTY_URI = URI.create("")
    }
}
