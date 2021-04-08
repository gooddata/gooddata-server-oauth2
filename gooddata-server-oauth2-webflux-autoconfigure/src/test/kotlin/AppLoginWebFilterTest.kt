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

import com.gooddata.oauth2.server.reactive.AppLoginWebFilter.Companion.APP_LOGIN_PATH
import com.gooddata.oauth2.server.reactive.AppLoginWebFilter.Companion.REDIRECT_TO
import io.mockk.called
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.http.server.RequestPath
import org.springframework.util.MultiValueMapAdapter
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono
import strikt.api.expectThat
import strikt.assertions.hasEntry
import java.net.URI

internal class AppLoginWebFilterTest {

    private val exchange: ServerWebExchange = mockk {
        every { response } returns mockk {
            every { setStatusCode(any()) } returns true
            every { headers } returns HttpHeaders()
        }
    }
    private val chain: WebFilterChain = mockk {
        every { filter(any()) } returns Mono.empty()
    }

    private val filter = AppLoginWebFilter(AppLoginProperties(URI.create("https://localhost:8443")))

    @Test
    fun `correct request is redirected`() {
        every { exchange.request } returns mockk {
            every { method } returns HttpMethod.GET
            every { path } returns RequestPath.parse(APP_LOGIN_PATH, "/")
            every { queryParams } returns MultiValueMapAdapter(mapOf(REDIRECT_TO to listOf("/some/path")))
        }

        filter.filter(exchange, chain).block()

        val response = exchange.response
        expectThat(response.headers) {
            hasEntry("Location", listOf("/some/path"))
        }
        verify(exactly = 1) { response.statusCode = HttpStatus.FOUND }
    }

    @Test
    fun `redirect to root is redirected`() {
        every { exchange.request } returns mockk {
            every { method } returns HttpMethod.GET
            every { path } returns RequestPath.parse(APP_LOGIN_PATH, "/")
            every { queryParams } returns MultiValueMapAdapter(mapOf(REDIRECT_TO to listOf("/")))
        }

        filter.filter(exchange, chain).block()

        val response = exchange.response
        expectThat(response.headers) {
            hasEntry("Location", listOf("/"))
        }
        verify(exactly = 1) { response.statusCode = HttpStatus.FOUND }
    }

    @Test
    fun `request with absolute path is not redirected if does not match configured origin`() {
        every { exchange.request } returns mockk {
            every { method } returns HttpMethod.GET
            every { path } returns RequestPath.parse(APP_LOGIN_PATH, "/")
            every { queryParams } returns MultiValueMapAdapter(mapOf(REDIRECT_TO to listOf("http://local/some/path")))
        }

        filter.filter(exchange, chain).block()

        val response = exchange.response
        verify { response wasNot called }
    }

    @Test
    fun `request with absolute path is redirected if matches configured origin`() {
        every { exchange.request } returns mockk {
            every { method } returns HttpMethod.GET
            every { path } returns RequestPath.parse(APP_LOGIN_PATH, "/")
            every { queryParams } returns
                MultiValueMapAdapter(mapOf(REDIRECT_TO to listOf("https://localhost:8443/some/path")))
        }

        filter.filter(exchange, chain).block()

        val response = exchange.response
        expectThat(response.headers) {
            hasEntry("Location", listOf("https://localhost:8443/some/path"))
        }
        verify(exactly = 1) { response.statusCode = HttpStatus.FOUND }
    }

    @Test
    fun `normalized uri is redirected if matches configured origin`() {
        every { exchange.request } returns mockk {
            every { method } returns HttpMethod.GET
            every { path } returns RequestPath.parse(APP_LOGIN_PATH, "/")
            every { queryParams } returns MultiValueMapAdapter(
                mapOf(REDIRECT_TO to listOf("https://localhost:8443/some/../path"))
            )
        }

        filter.filter(exchange, chain).block()

        val response = exchange.response
        expectThat(response.headers) {
            hasEntry("Location", listOf("https://localhost:8443/path"))
        }
        verify(exactly = 1) { response.statusCode = HttpStatus.FOUND }
    }

    @Test
    fun `normalized uri not redirected if does not match configured origin`() {
        every { exchange.request } returns mockk {
            every { method } returns HttpMethod.GET
            every { path } returns RequestPath.parse(APP_LOGIN_PATH, "/")
            every { queryParams } returns MultiValueMapAdapter(
                mapOf(REDIRECT_TO to listOf("http://local/some/../path"))
            )
        }

        filter.filter(exchange, chain).block()

        val response = exchange.response
        verify { response wasNot called }
    }

    @Test
    fun `request with incorrect method is not redirected`() {
        every { exchange.request } returns mockk {
            every { method } returns HttpMethod.POST
            every { path } returns RequestPath.parse(APP_LOGIN_PATH, "/")
            every { queryParams } returns MultiValueMapAdapter(mapOf(REDIRECT_TO to listOf("/some/path")))
        }

        filter.filter(exchange, chain).block()

        val response = exchange.response
        verify { response wasNot called }
    }

    @Test
    fun `request with incorrect path is not redirected`() {
        every { exchange.request } returns mockk {
            every { method } returns HttpMethod.GET
            every { path } returns RequestPath.parse("/some/other/path", "/")
            every { queryParams } returns MultiValueMapAdapter(mapOf(REDIRECT_TO to listOf("/some/path")))
        }

        filter.filter(exchange, chain).block()

        val response = exchange.response
        verify { response wasNot called }
    }

    @Test
    fun `request without query is not redirected`() {
        every { exchange.request } returns mockk {
            every { method } returns HttpMethod.GET
            every { path } returns RequestPath.parse(APP_LOGIN_PATH, "/")
            every { queryParams } returns MultiValueMapAdapter(mapOf())
        }

        filter.filter(exchange, chain).block()

        val response = exchange.response
        verify { response wasNot called }
    }

    @Test
    fun `request with double slash is not redirected`() {
        every { exchange.request } returns mockk {
            every { method } returns HttpMethod.GET
            every { path } returns RequestPath.parse(APP_LOGIN_PATH, "/")
            every { queryParams } returns MultiValueMapAdapter(mapOf(REDIRECT_TO to listOf("//doubleslash")))
        }

        filter.filter(exchange, chain).block()

        val response = exchange.response
        verify { response wasNot called }
    }

    @Test
    fun `request with backslash is not redirected`() {
        every { exchange.request } returns mockk {
            every { method } returns HttpMethod.GET
            every { path } returns RequestPath.parse(APP_LOGIN_PATH, "/")
            every { queryParams } returns MultiValueMapAdapter(mapOf(REDIRECT_TO to listOf("\\backslash")))
        }

        filter.filter(exchange, chain).block()

        val response = exchange.response
        verify { response wasNot called }
    }

    @Test
    fun `request with empty redirectTo is redirected`() {
        every { exchange.request } returns mockk {
            every { method } returns HttpMethod.GET
            every { path } returns RequestPath.parse(APP_LOGIN_PATH, "/")
            every { queryParams } returns MultiValueMapAdapter(mapOf(REDIRECT_TO to listOf("")))
        }

        filter.filter(exchange, chain).block()

        val response = exchange.response
        verify { response wasNot called }
    }

    @Test
    fun `request with null redirectTo is redirected`() {
        every { exchange.request } returns mockk {
            every { method } returns HttpMethod.GET
            every { path } returns RequestPath.parse(APP_LOGIN_PATH, "/")
            every { queryParams } returns MultiValueMapAdapter(mapOf(REDIRECT_TO to null))
        }

        filter.filter(exchange, chain).block()

        val response = exchange.response
        verify { response wasNot called }
    }
}
