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
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.web.server.savedrequest.ServerRequestCache
import org.springframework.util.MultiValueMapAdapter
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import strikt.api.expectThat
import strikt.assertions.isEmpty
import strikt.assertions.isEqualTo
import strikt.assertions.isTrue
import java.net.URI
import java.util.Optional

internal class HostBasedServerAuthenticationEntryPointTest {

    private val exchange: ServerWebExchange = mockk()

    private val requestCache: ServerRequestCache = mockk()

    private val entryPoint = HostBasedServerAuthenticationEntryPoint(requestCache)

    @Test
    fun `sends redirect`() {
        every { exchange.request.uri.host } returns "host"
        every { exchange.request.path.contextPath().value() } returns ""
        every { exchange.request.headers } returns HttpHeaders()
        every { exchange.response.setStatusCode(any()) } returns true
        every { exchange.response.headers.location = any() } returns Unit
        every { requestCache.saveRequest(any()) } returns Mono.empty()

        val response = entryPoint.commence(exchange, BadCredentialsException("msg"))

        expectThat(response.blockOptional()) {
            get(Optional<Void>::isEmpty).isTrue()
        }

        verify(exactly = 1) { exchange.response.statusCode = HttpStatus.FOUND }
        verify(exactly = 1) { exchange.response.headers.location = URI.create("/oauth2/authorization/host") }
    }

    @Test
    fun `sends unauthorized for XMLHttpRequest`() {
        val slot = slot<Mono<DataBuffer>>()
        val bytes = slot<ByteArray>()

        every { exchange.request.uri.host } returns "host"
        every { exchange.request.path.contextPath().value() } returns ""
        every { exchange.request.headers } returns HttpHeaders(
            MultiValueMapAdapter(
                mapOf("X-Requested-With" to listOf("XMLHttpRequest"))
            )
        )
        every { exchange.response.setStatusCode(any()) } returns true
        every { exchange.response.headers } returns HttpHeaders()
        every { exchange.response.writeWith(capture(slot)) } answers {
            slot.captured.then()
        }
        every { exchange.response.bufferFactory().wrap(capture(bytes)) } returns mockk()
        every { requestCache.saveRequest(any()) } returns Mono.empty()

        val response = entryPoint.commence(exchange, BadCredentialsException("msg"))

        expectThat(response.blockOptional()) {
            get(Optional<Void>::isEmpty).isTrue()
        }

        val httpResponse = exchange.response
        verify(ordering = Ordering.ORDERED) {
            httpResponse.statusCode = HttpStatus.FOUND
            httpResponse.statusCode = HttpStatus.UNAUTHORIZED
        }
        expectThat(httpResponse.headers).isEmpty()
        expectThat(bytes.captured).isEqualTo("/appLogin".toByteArray())
    }
}
