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

import java.net.URI
import org.slf4j.LoggerFactory
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.server.DefaultServerRedirectStrategy
import org.springframework.security.web.server.ServerAuthenticationEntryPoint
import org.springframework.security.web.server.savedrequest.ServerRequestCache
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

/**
 * [ServerAuthenticationEntryPoint] handles `XMLHttpRequest` are first redirected to `/appLogin` URI with
 * `401 Unauthorized` to allow JS apps to properly handle browser redirects. All other requests are redirected directly
 * to `/oauth2/authorization/{hostname}` using `302 Found` status code and `Location` header. It generates dynamic
 * redirects based on request's `Host` header as individual Auth2 providers are not defined statically during
 * Spring Context bootstrap.
 */
class TestEndpointDedicatedServerAuthenticationEntryPoint(
    private val requestCache: ServerRequestCache
) : ServerAuthenticationEntryPoint {

    companion object {
        private val logger = LoggerFactory.getLogger(TestEndpointDedicatedServerAuthenticationEntryPoint::class.java)
        const val TEST_ENDPOINT_REGISTRATION_ID_PREFIX = "test-"
        const val TEST_ENDPOINT_URL = "/api/v1/actions/organization/testIdp/**"
    }

    private val redirectStrategy = DefaultServerRedirectStrategy()

    override fun commence(exchange: ServerWebExchange, e: AuthenticationException?): Mono<Void> {
        val idpId = extractIdpId(exchange)

        if (idpId == null) {
            logger.error("Failed to extract idpId from request: ${exchange.request.path}")
            return Mono.error(IllegalArgumentException("Invalid request path for test endpoint."))
        }

        val registrationId = "$TEST_ENDPOINT_REGISTRATION_ID_PREFIX$idpId"
        val uri = URI.create("/oauth2/authorization/$registrationId")
        return requestCache
            .saveRequest(exchange)
            .then(redirectStrategy.sendRedirect(exchange, uri))
    }


    private fun extractIdpId(exchange: ServerWebExchange): String? {
        // Extract from path patterns
        val pathSegments = exchange.request.path.pathWithinApplication().value()
            .split("/").filter { it.isNotEmpty() }

        if (pathSegments.size >= 5) {
            when {
                // Pattern: /api/v1/actions/organization/testIdp/{idpId}
                pathSegments.size >= 5 &&
                    pathSegments[0] == "api" &&
                    pathSegments[1] == "v1" &&
                    pathSegments[2] == "actions" &&
                    pathSegments[3] == "organization" &&
                    pathSegments[4] == "testIdp" -> {
                    return pathSegments[5] // The idpId segment
                }
            }
        }
        return null
    }
}
