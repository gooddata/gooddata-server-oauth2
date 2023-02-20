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

import org.springframework.http.HttpStatus
import org.springframework.security.web.server.DefaultServerRedirectStrategy
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.net.URI

/**
 * [org.springframework.security.web.server.ServerRedirectStrategy] that uses `401 Unauthorized` instead of `302 Found`
 * and that sends redirect URI in response body instead of `Location` header.
 */
class XMLHttpRequestServerRedirectStrategy : DefaultServerRedirectStrategy() {

    override fun sendRedirect(serverExchange: ServerWebExchange, location: URI): Mono<Void> =
        // ensure proper redirect URI, then convert to UNAUTHORIZED instead
        Mono.just(serverExchange)
            // we need to handle the exchange changing side effect from the original sendRedirect
            // therefore, we need to emit a new mono with the input exchange
            .flatMap { exchange -> super.sendRedirect(exchange, location).then(Mono.just(exchange)) }
            .flatMap { exchange -> convertToUnauthorized(exchange) }

    private fun convertToUnauthorized(exchange: ServerWebExchange): Mono<Void> {
        val response = exchange.response
        val uri = response.headers.location ?: error("Location header not defined after the sendRedirect.")
        // clear location header
        response.headers.location = null
        // change redirect to UNAUTHORIZED
        response.statusCode = HttpStatus.UNAUTHORIZED
        return response.writeWith(
            Mono.just(response.bufferFactory().wrap(uri.toASCIIString().toByteArray()))
        )
    }
}
