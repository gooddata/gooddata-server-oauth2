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

    override fun sendRedirect(exchange: ServerWebExchange, location: URI): Mono<Void> =
        mono {
            super.sendRedirect(exchange, location).awaitOrNull()

            val response = exchange.response
            val uri = response.headers.location!!
            response.headers.location = null
            response.statusCode = HttpStatus.UNAUTHORIZED
            response.writeWith(
                mono {
                    response.bufferFactory().wrap(uri.toASCIIString().toByteArray())
                }
            ).awaitOrNull()
        }
}
