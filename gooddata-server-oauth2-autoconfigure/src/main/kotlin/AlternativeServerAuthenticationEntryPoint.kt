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

import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.server.DefaultServerRedirectStrategy
import org.springframework.security.web.server.ServerAuthenticationEntryPoint
import org.springframework.security.web.server.savedrequest.ServerRequestCache
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.net.URI
import org.slf4j.LoggerFactory

/**
 * [ServerAuthenticationEntryPoint] handles `XMLHttpRequest` are first redirected to `/appLogin` URI with
 * `401 Unauthorized` to allow JS apps to properly handle browser redirects. All other requests are redirected directly
 * to `/oauth2/authorization/{hostname}` using `302 Found` status code and `Location` header. It generates dynamic
 * redirects based on request's `Host` header as individual Auth2 providers are not defined statically during
 * Spring Context bootstrap.
 */
class AlternativeServerAuthenticationEntryPoint(
    private val requestCache: ServerRequestCache
) : ServerAuthenticationEntryPoint {

    companion object {
        private val logger = LoggerFactory.getLogger(AlternativeServerAuthenticationEntryPoint::class.java)
    }

    private val redirectStrategy = DefaultServerRedirectStrategy()
    private val xmlHttpRequestServerRedirectStrategy = XMLHttpRequestServerRedirectStrategy()

    override fun commence(exchange: ServerWebExchange, e: AuthenticationException?): Mono<Void> {
        val requestPath = exchange.request.uri.path
        logger.info("DEBUG: 🚀 Alternative Authentication Entry Point - Path: {} | Exception: {}", requestPath, e?.message)

        // TODO IS the Ajax call processing needed?
        return if (exchange.isAjaxCall()) {
            val uri = URI.create(AppLoginUri.PATH)
            logger.info("DEBUG: 🚀 Alternative Entry Point - Redirecting AJAX to: {}", uri)
            xmlHttpRequestServerRedirectStrategy.sendRedirect(exchange, uri)
        } else {
            // Extract idpId from the request (could be from path, query param, or header)
            val idpId = extractIdpId(exchange) ?: "defaultIdp"
            // Use the same registration ID pattern that the alternative repository expects
            // TODO: COULD WE RELY ON A DIFFERENT MECHANISM TO DIFFERENTIATE AMONG THE ALTERNATIVE VS STANDARD auth flows?
            val registrationId = "test-$idpId"
            val uri = URI.create("/oauth2/authorization/test-${exchange.request.uri.host}")
            logger.info("DEBUG: 🚀 Alternative Entry Point - Redirecting to: {} | IDP ID: {} | Registration ID: {}", uri, idpId, registrationId)
            requestCache
                .saveRequest(exchange)
                .then(redirectStrategy.sendRedirect(exchange, uri))
        }
    }

    private fun extractIdpId(exchange: ServerWebExchange): String? {
        // Extract from query parameter
        return exchange.request.queryParams["idp_id"]?.firstOrNull()?.let { return it }
    }

    private fun ServerWebExchange.isAjaxCall() =
        this.request.headers["X-Requested-With"]?.first() == "XMLHttpRequest"
}
