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

import org.junit.jupiter.api.Test
import org.springframework.http.HttpStatus
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import strikt.api.expectThat
import strikt.assertions.isEmpty
import strikt.assertions.isEqualTo
import strikt.assertions.isNotNull
import java.net.URI

internal class XMLHttpRequestServerRedirectStrategyTest {

    private val strategy = XMLHttpRequestServerRedirectStrategy()

    @Test
    fun `sends 401 Unauthorized with location in body`() {
        val exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api").contextPath(""))

        strategy.sendRedirect(exchange, URI.create("/location")).block()

        expectThat(exchange.response.headers).isEmpty()
        expectThat(exchange.response.statusCode).isEqualTo(HttpStatus.UNAUTHORIZED)
        expectThat(exchange.response.body.blockFirst())
            .isNotNull()
            .get { asInputStream().readAllBytes() }.isEqualTo("/location".toByteArray())
    }
}
