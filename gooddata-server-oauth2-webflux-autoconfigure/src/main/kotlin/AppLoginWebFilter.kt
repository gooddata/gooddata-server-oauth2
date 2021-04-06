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

import kotlinx.coroutines.reactor.mono
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
class AppLoginWebFilter(properties: AppLoginProperties) : WebFilter {

    private val matcher = AndServerWebExchangeMatcher(
        ServerWebExchangeMatchers.pathMatchers(HttpMethod.GET, APP_LOGIN_PATH),
        ServerWebExchangeMatcher {
            it.request.queryParams[REDIRECT_TO]
                ?.firstOrNull()
                ?.let { redirectTo -> kotlin.runCatching { URI.create(redirectTo).normalize() }.getOrNull() }
                ?.takeIf { redirectTo ->
                    val uri = UriComponentsBuilder.fromUri(redirectTo)
                        .replacePath(null)
                        .replaceQuery(null)
                        .fragment(null)
                        .build().toUri()
                    uri == properties.allowRedirect || (uri == EMPTY_URI && redirectTo.path.startsWith("/"))
                }
                ?.let { redirectTo ->
                    ServerWebExchangeMatcher.MatchResult.match(mapOf(REDIRECT_TO to redirectTo.toASCIIString()))
                } ?: ServerWebExchangeMatcher.MatchResult.notMatch()
        }
    )
    private val redirectStrategy = DefaultServerRedirectStrategy()

    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> = mono {
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

    companion object {
        const val APP_LOGIN_PATH = "/appLogin"
        internal const val REDIRECT_TO = "redirectTo"
        private val EMPTY_URI = URI.create("")
    }
}
