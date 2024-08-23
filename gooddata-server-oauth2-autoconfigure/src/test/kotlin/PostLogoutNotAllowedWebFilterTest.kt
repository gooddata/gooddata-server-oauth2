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

import io.mockk.called
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.http.server.RequestPath
import org.springframework.web.server.ResponseStatusException
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono
import strikt.api.expectThrows
import strikt.assertions.isEqualTo

internal class PostLogoutNotAllowedWebFilterTest {

    private val exchange: ServerWebExchange = mockk()
    private val chain: WebFilterChain = mockk {
        every { filter(any()) } returns Mono.empty()
    }

    private val filter = PostLogoutNotAllowedWebFilter()

    @Test
    fun `POST logout is processed`() {
        every { exchange.request } returns mockk {
            every { method } returns HttpMethod.POST
            every { path } returns RequestPath.parse("/logout", "/")
        }

        expectThrows<ResponseStatusException> { filter.filter(exchange, chain).block() }
            .get { statusCode }.isEqualTo(HttpStatus.METHOD_NOT_ALLOWED)
    }

    @Test
    fun `POST logout all is processed`() {
        every { exchange.request } returns mockk {
            every { method } returns HttpMethod.POST
            every { path } returns RequestPath.parse("/logout/all", "/")
        }

        expectThrows<ResponseStatusException> { filter.filter(exchange, chain).block() }
            .get { statusCode }.isEqualTo(HttpStatus.METHOD_NOT_ALLOWED)
    }

    @Test
    fun `GET logout is ignored`() {
        every { exchange.request } returns mockk {
            every { method } returns HttpMethod.GET
            every { path } returns RequestPath.parse("/logout", "/")
        }

        filter.filter(exchange, chain).block()

        verify { exchange.response wasNot called }
    }

    @Test
    fun `GET logout all is ignored`() {
        every { exchange.request } returns mockk {
            every { method } returns HttpMethod.GET
            every { path } returns RequestPath.parse("/logout/all", "/")
        }

        filter.filter(exchange, chain).block()

        verify { exchange.response wasNot called }
    }
}
