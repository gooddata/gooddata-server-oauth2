/*
 * Copyright 2025 GoodData Corporation
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

import org.slf4j.LoggerFactory
import org.springframework.security.core.Authentication
import org.springframework.security.web.server.DefaultServerRedirectStrategy
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.net.URI

/**
 * Custom authentication success handler that detects alternative authentication flows
 * and redirects users to the organization main page instead of the original API endpoint.
 */
// TODO COULD WE REPLACE IT WITH A REDIRECT DIRECTLY FROM THE /testIdp endpoint??
class AlternativeAuthenticationSuccessHandler(
    private val fallbackSuccessHandler: ServerAuthenticationSuccessHandler
) : ServerAuthenticationSuccessHandler {

    companion object {
        private val logger = LoggerFactory.getLogger(AlternativeAuthenticationSuccessHandler::class.java)

        // Patterns that indicate alternative authentication flows
        private val ALTERNATIVE_AUTH_PATTERNS = listOf(
            "/api/v1/actions/organization/testIdp/",
            "/login/oauth2/code/test-"
        )
    }

    private val redirectStrategy = DefaultServerRedirectStrategy()

    override fun onAuthenticationSuccess(
        webFilterExchange: WebFilterExchange,
        authentication: Authentication
    ): Mono<Void> {
        val exchange = webFilterExchange.exchange
        val referrer = exchange.request.headers.getFirst("Referer")
        val currentPath = exchange.request.uri.path

        logger.info("DEBUG: 🎯 AlternativeAuthenticationSuccessHandler - Current path: {}, Referrer: {}", currentPath, referrer)

        // Check if this looks like an alternative auth flow based on referrer or stored state
        return if (isAlternativeAuthFlow(referrer) || isAlternativeAuthFlow(currentPath)) {
            // Alternative auth flow - redirect to main page
            val mainPageUri = buildMainPageUri(exchange)
            logger.info("DEBUG: 🎯 AlternativeAuthenticationSuccessHandler - Redirecting to main page: {}", mainPageUri)

            redirectStrategy.sendRedirect(exchange, mainPageUri)
        } else {
            // Not an alternative auth flow, use the fallback handler
            logger.info("DEBUG: 🎯 AlternativeAuthenticationSuccessHandler - Using fallback handler")
            fallbackSuccessHandler.onAuthenticationSuccess(webFilterExchange, authentication)
        }
    }

    private fun buildMainPageUri(exchange: ServerWebExchange): URI {
        val hostname = exchange.request.uri.host
        val port = exchange.request.uri.port
        val scheme = exchange.request.uri.scheme

        return if (port == -1 || (scheme == "https" && port == 443) || (scheme == "http" && port == 80)) {
            URI.create("$scheme://$hostname/")
        } else {
            URI.create("$scheme://$hostname:$port/")
        }
    }

    private fun isAlternativeAuthFlow(uri: String?): Boolean {
        return uri != null && ALTERNATIVE_AUTH_PATTERNS.any { pattern -> uri.contains(pattern) }
    }
}
