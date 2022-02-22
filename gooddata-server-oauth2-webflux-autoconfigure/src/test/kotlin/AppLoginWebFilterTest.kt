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

import com.gooddata.oauth2.server.common.AppLoginProperties
import com.gooddata.oauth2.server.common.AuthenticationStoreClient
import com.gooddata.oauth2.server.common.Organization
import com.gooddata.oauth2.server.reactive.AppLoginWebFilter.Companion.APP_LOGIN_PATH
import com.gooddata.oauth2.server.reactive.AppLoginWebFilter.Companion.REDIRECT_TO
import io.mockk.called
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.http.server.RequestPath
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.util.MultiValueMapAdapter
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono
import strikt.api.expectThat
import strikt.assertions.hasEntry
import java.net.URI

internal class AppLoginWebFilterTest {

    private val client: AuthenticationStoreClient = mockk()

    private val exchange: ServerWebExchange = mockk {
        every { response } returns mockk {
            every { setStatusCode(any()) } returns true
            every { headers } returns HttpHeaders()
        }
    }
    private val chain: WebFilterChain = mockk {
        every { filter(any()) } returns Mono.empty()
    }

    private val filter = AppLoginWebFilter(
        AppLoginProperties(URI.create(GLOBAL_ALLOWED_URI)),
        client
    )

    @BeforeEach
    internal fun setUp() {
        val organization = Organization(
            id = "organizationId",
            allowedOrigins = ALLOWED_ORIGINS
        )
        coEvery { client.getOrganizationByHostname("localhost") } returns organization
    }

    @Test
    fun `correct request is redirected`() {
        every { exchange.request } returns mockk {
            mockUri()
            every { method } returns HttpMethod.GET
            every { path } returns REQUEST_PATH
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
            mockUri()
            every { method } returns HttpMethod.GET
            every { path } returns REQUEST_PATH
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
            mockUri()
            every { method } returns HttpMethod.GET
            every { path } returns REQUEST_PATH
            every { queryParams } returns MultiValueMapAdapter(mapOf(REDIRECT_TO to listOf("http://local/some/path")))
        }

        filter.filter(exchange, chain).block()

        val response = exchange.response
        verify { response wasNot called }
    }

    @ParameterizedTest
    @MethodSource("hosts")
    fun `request with absolute path is redirected if matches configured origin`(host: String) {
        every { exchange.request } returns mockk {
            mockUri()
            every { method } returns HttpMethod.GET
            every { path } returns REQUEST_PATH
            every { queryParams } returns
                MultiValueMapAdapter(mapOf(REDIRECT_TO to listOf("$host/some/path")))
        }

        filter.filter(exchange, chain).block()

        val response = exchange.response
        expectThat(response.headers) {
            hasEntry("Location", listOf("$host/some/path"))
        }
        verify(exactly = 1) { response.statusCode = HttpStatus.FOUND }
    }

    @ParameterizedTest
    @MethodSource("hosts")
    fun `normalized uri is redirected if matches configured origin`(host: String) {
        every { exchange.request } returns mockk {
            mockUri()
            every { method } returns HttpMethod.GET
            every { path } returns REQUEST_PATH
            every { queryParams } returns MultiValueMapAdapter(
                mapOf(REDIRECT_TO to listOf("$host/some/../path"))
            )
        }

        filter.filter(exchange, chain).block()

        val response = exchange.response
        expectThat(response.headers) {
            hasEntry("Location", listOf("$host/path"))
        }
        verify(exactly = 1) { response.statusCode = HttpStatus.FOUND }
    }

    @Test
    fun `normalized uri not redirected if does not match configured origin`() {
        every { exchange.request } returns mockk {
            mockUri()
            every { method } returns HttpMethod.GET
            every { path } returns REQUEST_PATH
            every { queryParams } returns MultiValueMapAdapter(
                mapOf(REDIRECT_TO to listOf("http://local/some/../path"))
            )
        }

        filter.filter(exchange, chain).block()

        val response = exchange.response
        verify { response wasNot called }
    }

    private fun ServerHttpRequest.mockUri(
        host: String = "localhost",
        port: Int = 8443,
        path: String = "$APP_LOGIN_PATH/"
    ) {
        every { uri } returns
            URI(
                null,
                null,
                host,
                port,
                path,
                null,
                null
            )
    }

    @Test
    fun `request with incorrect method is not redirected`() {
        every { exchange.request } returns mockk {
            every { method } returns HttpMethod.POST
            every { path } returns REQUEST_PATH
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
            every { path } returns REQUEST_PATH
            every { queryParams } returns MultiValueMapAdapter(mapOf())
        }

        filter.filter(exchange, chain).block()

        val response = exchange.response
        verify { response wasNot called }
    }

    @Test
    fun `request with double slash is not redirected`() {
        every { exchange.request } returns mockk {
            mockUri()
            every { method } returns HttpMethod.GET
            every { path } returns REQUEST_PATH
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
            every { path } returns REQUEST_PATH
            every { queryParams } returns MultiValueMapAdapter(mapOf(REDIRECT_TO to listOf("\\backslash")))
        }

        filter.filter(exchange, chain).block()

        val response = exchange.response
        verify { response wasNot called }
    }

    @Test
    fun `request with empty redirectTo is redirected`() {
        every { exchange.request } returns mockk {
            mockUri()
            every { method } returns HttpMethod.GET
            every { path } returns REQUEST_PATH
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
            every { path } returns REQUEST_PATH
            every { queryParams } returns MultiValueMapAdapter(mapOf(REDIRECT_TO to null))
        }

        filter.filter(exchange, chain).block()

        val response = exchange.response
        verify { response wasNot called }
    }

    companion object {
        private val REQUEST_PATH = RequestPath.parse(APP_LOGIN_PATH, "/")
        private const val GLOBAL_ALLOWED_URI = "https://localhost:8443"

        private const val ORGANIZATION_ALLOWED_URI = "https://some.host.com"
        private const val ORGANIZATION_ALLOWED_URI2 = "http://domain.cz:1234"

        private val ALLOWED_ORIGINS = listOf(ORGANIZATION_ALLOWED_URI, ORGANIZATION_ALLOWED_URI2)

        @JvmStatic
        fun hosts() = ALLOWED_ORIGINS + GLOBAL_ALLOWED_URI
    }
}
