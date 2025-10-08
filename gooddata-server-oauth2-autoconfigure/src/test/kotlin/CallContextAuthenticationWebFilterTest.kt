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

import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.springframework.http.HttpHeaders
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono

class CallContextAuthenticationWebFilterTest {

    companion object {
        private const val TEST_HEADER_NAME = "X-Test-Context"
    }

    private val headerProcessor: CallContextHeaderProcessor = mockk {
        every { getHeaderName() } returns TEST_HEADER_NAME
    }
    private val filter = CallContextAuthenticationWebFilter(headerProcessor)

    private val exchange: ServerWebExchange = mockk(relaxed = true) {
        every { request } returns mockk {
            every { headers } returns mockk<HttpHeaders>()
            every { remoteAddress } returns mockk {
                every { address } returns mockk {
                    every { hostAddress } returns "10.0.0.1"
                }
            }
        }
    }

    private val chain: WebFilterChain = mockk {
        every { filter(any()) } returns Mono.empty()
    }

    @Test
    fun `no header present continues to next filter`() {
        every { exchange.request.headers.getFirst(TEST_HEADER_NAME) } returns null

        filter.filter(exchange, chain).block()

        verify(exactly = 1) { headerProcessor.getHeaderName() }
        verify(exactly = 1) { chain.filter(exchange) }
        verify(exactly = 0) { headerProcessor.parseCallContextHeader(any()) }
    }

    @Test
    fun `no processor configured continues to next filter`() {
        val filterWithoutProcessor = CallContextAuthenticationWebFilter(null)
        every { exchange.request.headers.getFirst(TEST_HEADER_NAME) } returns "header-value"

        filterWithoutProcessor.filter(exchange, chain).block()

        verify(exactly = 1) { chain.filter(exchange) }
    }

    @Test
    fun `valid header with all required fields creates authentication token`() {
        val headerValue = "valid-header-value"
        val authDetails = CallContextAuth(
            organizationId = "org123",
            userId = "user456",
            authMethod = "API_TOKEN",
            tokenId = "token789"
        )

        every { exchange.request.headers.getFirst(TEST_HEADER_NAME) } returns headerValue
        every { headerProcessor.parseCallContextHeader(headerValue) } returns authDetails

        filter.filter(exchange, chain).block()

        verify(exactly = 1) { headerProcessor.getHeaderName() }
        verify(exactly = 1) { headerProcessor.parseCallContextHeader(headerValue) }
        verify(exactly = 1) { chain.filter(exchange) }
    }

    @Test
    fun `null auth details skips CallContext authentication`() {
        val headerValue = "incomplete-header"

        every { exchange.request.headers.getFirst(TEST_HEADER_NAME) } returns headerValue
        every { headerProcessor.parseCallContextHeader(headerValue) } returns null

        filter.filter(exchange, chain).block()

        verify(exactly = 1) { headerProcessor.parseCallContextHeader(headerValue) }
        verify(exactly = 1) { chain.filter(exchange) }
    }

    @Test
    fun `auth details without tokenId works correctly`() {
        val headerValue = "header-without-token"
        val authDetails = CallContextAuth(
            organizationId = "org123",
            userId = "user456",
            authMethod = "JWT"
        )

        every { exchange.request.headers.getFirst(TEST_HEADER_NAME) } returns headerValue
        every { headerProcessor.parseCallContextHeader(headerValue) } returns authDetails

        filter.filter(exchange, chain).block()

        verify(exactly = 1) { headerProcessor.parseCallContextHeader(headerValue) }
        verify(exactly = 1) { chain.filter(exchange) }
    }

    @Test
    fun `header processor throws exception falls back to normal auth`() {
        val headerValue = "malformed-header"

        every { exchange.request.headers.getFirst(TEST_HEADER_NAME) } returns headerValue
        every { headerProcessor.parseCallContextHeader(headerValue) } throws
            IllegalStateException("Invalid format")

        filter.filter(exchange, chain).block()

        verify(exactly = 1) { headerProcessor.parseCallContextHeader(headerValue) }
        verify(exactly = 1) { chain.filter(exchange) }
    }
}
