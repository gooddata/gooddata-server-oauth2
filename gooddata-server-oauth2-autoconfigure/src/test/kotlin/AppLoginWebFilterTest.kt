/*
 * Copyright 2022 GoodData Corporation
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

import io.mockk.called
import io.mockk.every
import io.mockk.invoke
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono
import strikt.api.expectThat
import strikt.assertions.hasEntry

@Suppress("ReactiveStreamsUnusedPublisher")
internal class AppLoginWebFilterTest {

    private val processor = mockk<AppLoginRedirectProcessor>()
    private val exchange = mockk<ServerWebExchange>(relaxed = true) {
        every { response } returns mockk {
            every { setStatusCode(any()) } returns true
            every { headers } returns HttpHeaders()
        }
    }
    private val chain = mockk<WebFilterChain> {
        every { filter(any()) } returns Mono.empty()
    }

    private val filter = AppLoginWebFilter(processor)

    @Test
    fun `extracted redirect uri is redirected`() {
        val process = slot<(String) -> Mono<Void>>()
        every { processor.process(exchange, capture(process), any()) } answers {
            process.invoke("/some/path")
        }

        filter.filter(exchange, chain).block()

        val response = exchange.response
        expectThat(response.headers) {
            hasEntry("Location", listOf("/some/path"))
        }
        verify(exactly = 1) { response.statusCode = HttpStatus.FOUND }
        verify { chain wasNot called }
    }

    @Test
    fun `empty redirect uri is not redirected`() {
        val default = slot<() -> Mono<Void>>()
        every { processor.process(exchange, any(), capture(default)) } answers {
            default.invoke()
        }

        filter.filter(exchange, chain).block()

        val response = exchange.response
        verify { response wasNot called }
        verify { chain.filter(exchange) }
    }
}
