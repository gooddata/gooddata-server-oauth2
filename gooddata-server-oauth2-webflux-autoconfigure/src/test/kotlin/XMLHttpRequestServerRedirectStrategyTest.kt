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

import io.mockk.Ordering
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.springframework.core.io.buffer.DataBuffer
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import strikt.api.expectThat
import strikt.assertions.isEmpty
import strikt.assertions.isEqualTo
import java.net.URI

internal class XMLHttpRequestServerRedirectStrategyTest {

    private val exchange: ServerWebExchange = mockk()

    private val strategy = XMLHttpRequestServerRedirectStrategy()

    @Test
    fun `sends 401 Unauthorized with location in body`() {
        val slot = slot<Mono<DataBuffer>>()
        val bytes = slot<ByteArray>()

        every { exchange.request.path.contextPath().value() } returns ""
        every { exchange.response.setStatusCode(any()) } returns true
        every { exchange.response.headers } returns HttpHeaders()
        every { exchange.response.writeWith(capture(slot)) } answers {
            slot.captured.then()
        }
        every { exchange.response.bufferFactory().wrap(capture(bytes)) } returns mockk()

        strategy.sendRedirect(exchange, URI.create("/location")).block()

        val httpResponse = exchange.response
        verify(ordering = Ordering.ORDERED) {
            httpResponse.statusCode = HttpStatus.FOUND
            httpResponse.statusCode = HttpStatus.UNAUTHORIZED
        }
        expectThat(httpResponse.headers).isEmpty()
        expectThat(bytes.captured).isEqualTo("/location".toByteArray())
    }
}
