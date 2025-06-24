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
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono

class IdpWebFilter : WebFilter {

    // Define which paths should trigger IDP context extraction
    // DO NOT include OAuth2 authorization URLs - let Spring Security handle those
    // TODO: DEFINE THE PATH ON A SINGLE PLACE AS A CONSTANT
    private val idpPathMatcher = OrServerWebExchangeMatcher(
        PathPatternParserServerWebExchangeMatcher("/api/v1/actions/organization/testIdp/**"),
    )

    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> {
        val requestPath = exchange.request.uri.path
        logger.info("DEBUG: 🔍 IdpWebFilter - Processing path: {}", requestPath)

        return idpPathMatcher.matches(exchange).flatMap { matchResult ->
            logger.info("DEBUG: 🔍 IdpWebFilter - Path: {} | Matches: {}", requestPath, matchResult.isMatch)

            if (matchResult.isMatch) {
                // Extract and store idpId for alternative auth endpoints
                val idpId = extractIdpId(exchange)
                logger.info("DEBUG: 🔍 IdpWebFilter - Extracted IDP ID: {} from path: {}", idpId, requestPath)

                if (idpId != null) {
                    logger.info("DEBUG: 🔍 IdpWebFilter - Adding IDP context: {}", idpId)
                    chain.filter(exchange).contextWrite {
                        it.put(IdpContext::class, IdpContext(idpId))
                    }
                } else {
                    logger.error(
                        "DEBUG: 🔍 IdpWebFilter - Missing IDP ID for alternative auth endpoint: {}",
                        requestPath
                    )
                    // Could return error or use default
                    Mono.error(IllegalArgumentException("Missing IDP ID for alternative auth endpoint"))
                }
            } else {
                logger.info("DEBUG: 🔍 IdpWebFilter - Not an alternative auth path, continuing: {}", requestPath)
                // Not an alternative auth path, continue without IDP context
                chain.filter(exchange)
            }
        }
    }

    // TODO: SHALL WE RELLY ON PATH SEGMENTS OR QUERY PARAMS?
    private fun extractIdpId(exchange: ServerWebExchange): String? {
        // Extract from query parameter: /api/v1/actions/organization/testIdp/something?idp_id=override
        exchange.request.queryParams["idp_id"]?.firstOrNull()?.let { return it }

        // Extract from path patterns
        val pathSegments = exchange.request.path.pathWithinApplication().value()
            .split("/").filter { it.isNotEmpty() }

        logger.info("DEBUG: 🔍 IdpWebFilter - Path segments: {}", pathSegments)

        // TODO: BETTER HANDLING OF ERRORS
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

    companion object {
        internal fun <T> Mono<T>.idpContextWrite(idpId: String) =
            contextWrite { it.put(IdpContext::class, IdpContext(idpId)) }

        private val logger = LoggerFactory.getLogger(IdpWebFilter::class.java)
    }
}

/**
 * The [IdpContext] is a context to store [IdpId] extracted from the alternative authentication request
 * and stored as context in [IdpWebFilter]
 */
data class IdpContext(val idpId: String)
