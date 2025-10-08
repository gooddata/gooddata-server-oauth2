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

import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono

private val logger = KotlinLogging.logger {}

/**
 * WebFilter that detects call context header and creates Spring Security authentication.
 *
 * This filter runs before the main authentication filters and takes precedence over Bearer token
 * authentication when the call context header is present AND contains user information.
 * The call context header should only come from trusted internal services.
 *
 * If the header is present with user info, it creates a [CallContextAuthenticationToken] that will be processed
 * by [CallContextAuthenticationProcessor].
 * If the header is absent or has no user info, the request continues to other authentication mechanisms.
 */
class CallContextAuthenticationWebFilter(
    private val headerProcessor: CallContextHeaderProcessor?
) : WebFilter {

    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> {
        // If no processor configured or no header, skip CallContext authentication
        val callContextHeader = headerProcessor?.getHeaderName()
            ?.let { exchange.request.headers.getFirst(it) }

        if (callContextHeader == null) {
            return chain.filter(exchange)
        }

        // Check if the CallContext has user information before creating an authentication token
        return try {
            val authDetails = headerProcessor?.parseCallContextHeader(callContextHeader)

            // Only proceed with CallContext authentication if we got auth details
            if (authDetails != null) {
                val remoteHost = exchange.request.remoteAddress?.address?.hostAddress ?: "unknown"
                logger.info {
                    "Call context authentication initiated from $remoteHost"
                }

                val authToken = CallContextAuthenticationToken(callContextHeader)
                val securityContext = SecurityContextImpl(authToken)

                chain.filter(exchange)
                    .contextWrite(
                        ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext))
                    )
            } else {
                // CallContext has no user info, skip and let the regular authentication chain handle it
                chain.filter(exchange)
            }
        } catch (@Suppress("TooGenericExceptionCaught") e: Exception) {
            // Must catch all exceptions for graceful fallback to normal auth
            val remoteHost = exchange.request.remoteAddress?.address?.hostAddress
            logger.warn(e) {
                "Failed to parse CallContext header from $remoteHost, " +
                    "falling back to normal authentication chain"
            }
            chain.filter(exchange)
        }
    }
}

/**
 * Exception thrown when CallContext authentication fails.
 */
class CallContextAuthenticationException(
    message: String,
    cause: Throwable? = null
) : RuntimeException(message, cause)
