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

import com.gooddata.oauth2.server.OrganizationWebFilter.Companion.orgContextWrite
import io.mockk.Called
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import org.springframework.http.HttpMethod
import org.springframework.http.server.RequestPath
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.util.MultiValueMapAdapter
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import strikt.api.expectCatching
import strikt.api.expectThat
import strikt.assertions.isA
import strikt.assertions.isEqualTo
import strikt.assertions.isFailure
import java.net.URI

@Suppress("ReactiveStreamsUnusedPublisher")
internal class AppLoginRedirectProcessorTest {
    private val client = mockk<AuthenticationStoreClient>()
    private val exchange = mockk<ServerWebExchange>()
    private val processor = AppLoginRedirectProcessor(
        AppLoginProperties(URI.create(GLOBAL_ALLOWED_URI)),
        client,
    )
    private val processFun = mockk<(String) -> Mono<Void>> {
        every { this@mockk.invoke(any()) } returns Mono.empty()
    }
    private val defaultFun = mockk<() -> Mono<Void>> {
        every { this@mockk.invoke() } returns Mono.empty()
    }

    @Test
    fun `redirect to relative path is processed`() {
        every { exchange.request } returns mockk {
            mockUri()
            every { method } returns HttpMethod.GET
            every { path } returns REQUEST_PATH
            every { queryParams } returns MultiValueMapAdapter(mapOf(AppLoginUri.REDIRECT_TO to listOf("/some/path")))
        }
        every { exchange.attributes[OrganizationWebFilter.ORGANIZATION_CACHE_KEY] } returns ORGANIZATION

        processor.process(exchange, processFun, defaultFun).block()
        verify { processFun("/some/path") }
        verify { defaultFun wasNot Called }
    }

    @Test
    fun `redirect to root path is processed`() {
        every { exchange.request } returns mockk {
            mockUri()
            every { method } returns HttpMethod.GET
            every { path } returns REQUEST_PATH
            every { queryParams } returns MultiValueMapAdapter(mapOf(AppLoginUri.REDIRECT_TO to listOf("/")))
        }

        processor.process(exchange, processFun, defaultFun).block()
        verify { processFun("/") }
        verify { defaultFun wasNot Called }
    }

    @Test
    fun `redirect to absolute path is not processed if does not match configured origin`() {
        every { exchange.request } returns mockk {
            mockUri()
            every { method } returns HttpMethod.GET
            every { path } returns REQUEST_PATH
            every { queryParams } returns MultiValueMapAdapter(
                mapOf(AppLoginUri.REDIRECT_TO to listOf("http://local/some/path"))
            )
        }
        every { exchange.attributes[OrganizationWebFilter.ORGANIZATION_CACHE_KEY] } returns ORGANIZATION

        expectException(
            { processor.process(exchange, processFun, defaultFun).orgContextWrite(ORGANIZATION).block() },
            "A redirection to the specified address not allowed."
        )

        verify { processFun wasNot Called }
        verify { defaultFun() wasNot Called }
    }

    @ParameterizedTest
    @MethodSource("hosts")
    fun `redirect to absolute path is processed if matches configured origin`(host: String) {
        every { exchange.request } returns mockk {
            mockUri()
            every { method } returns HttpMethod.GET
            every { path } returns REQUEST_PATH
            every { queryParams } returns
                MultiValueMapAdapter(mapOf(AppLoginUri.REDIRECT_TO to listOf("$host/some/path")))
        }
        every { exchange.attributes[OrganizationWebFilter.ORGANIZATION_CACHE_KEY] } returns ORGANIZATION

        processor.process(exchange, processFun, defaultFun).orgContextWrite(ORGANIZATION).block()
        verify { processFun("$host/some/path") }
        verify { defaultFun wasNot Called }
    }

    @ParameterizedTest
    @MethodSource("hosts")
    fun `redirect to uri is processed if its normalized form matches configured origin`(host: String) {
        every { exchange.request } returns mockk {
            mockUri()
            every { method } returns HttpMethod.GET
            every { path } returns REQUEST_PATH
            every { queryParams } returns MultiValueMapAdapter(
                mapOf(AppLoginUri.REDIRECT_TO to listOf("$host/some/../path"))
            )
        }
        every { exchange.attributes[OrganizationWebFilter.ORGANIZATION_CACHE_KEY] } returns ORGANIZATION

        processor.process(exchange, processFun, defaultFun).orgContextWrite(ORGANIZATION).block()
        verify { processFun("$host/path") }
        verify { defaultFun wasNot Called }
    }

    @Test
    fun `redirect to uri is not processed if its normalized form does not match configured origin`() {
        every { exchange.request } returns mockk {
            mockUri()
            every { method } returns HttpMethod.GET
            every { path } returns REQUEST_PATH
            every { queryParams } returns MultiValueMapAdapter(
                mapOf(AppLoginUri.REDIRECT_TO to listOf("http://local/some/../path"))
            )
        }
        every { exchange.attributes[OrganizationWebFilter.ORGANIZATION_CACHE_KEY] } returns ORGANIZATION

        expectException(
            { processor.process(exchange, processFun, defaultFun).orgContextWrite(ORGANIZATION).block() },
            "A redirection to the specified address not allowed."
        )

        verify { processFun wasNot Called }
        verify { defaultFun() wasNot Called }
    }

    @Test
    fun `redirect for an incorrect method is not processed`() {
        every { exchange.request } returns mockk {
            every { method } returns HttpMethod.POST
            every { path } returns REQUEST_PATH
            every { queryParams } returns MultiValueMapAdapter(mapOf(AppLoginUri.REDIRECT_TO to listOf("/some/path")))
        }

        processor.process(exchange, processFun, defaultFun).block()
        verify { processFun wasNot Called }
        verify { defaultFun() }
    }

    @Test
    fun `redirect for an incorrect path is not processed`() {
        every { exchange.request } returns mockk {
            every { method } returns HttpMethod.GET
            every { path } returns RequestPath.parse("/some/other/path", "/")
            every { queryParams } returns MultiValueMapAdapter(mapOf(AppLoginUri.REDIRECT_TO to listOf("/some/path")))
        }

        processor.process(exchange, processFun, defaultFun).block()
        verify { processFun wasNot Called }
        verify { defaultFun() }
    }

    @Test
    fun `request without redirect query is not processed`() {
        every { exchange.request } returns mockk {
            every { method } returns HttpMethod.GET
            every { path } returns REQUEST_PATH
            every { queryParams } returns MultiValueMapAdapter(mapOf())
        }

        expectException(
            { processor.process(exchange, processFun, defaultFun).block() },
            "Query param \"redirectTo\" not found"
        )

        verify { processFun wasNot Called }
        verify { defaultFun() wasNot Called }
    }

    @Test
    fun `redirect to path with double slash is not processed`() {
        every { exchange.request } returns mockk {
            mockUri()
            every { method } returns HttpMethod.GET
            every { path } returns REQUEST_PATH
            every { queryParams } returns MultiValueMapAdapter(
                mapOf(AppLoginUri.REDIRECT_TO to listOf("//doubleslash"))
            )
        }

        expectException(
            { processor.process(exchange, processFun, defaultFun).orgContextWrite(ORGANIZATION).block() },
            "A redirection to the specified address not allowed."
        )

        verify { processFun wasNot Called }
        verify { defaultFun() wasNot Called }
    }

    @Test
    fun `redirect to path with backslash is not processed`() {
        every { exchange.request } returns mockk {
            every { method } returns HttpMethod.GET
            every { path } returns REQUEST_PATH
            every { queryParams } returns MultiValueMapAdapter(mapOf(AppLoginUri.REDIRECT_TO to listOf("\\backslash")))
        }

        expectException(
            { processor.process(exchange, processFun, defaultFun).block() },
            "URL normalization error: Illegal character in path at index 0: \\backslash"
        )

        verify { processFun wasNot Called }
        verify { defaultFun() wasNot Called }
    }

    @Test
    fun `empty redirect query param is not processed`() {
        every { exchange.request } returns mockk {
            mockUri()
            every { method } returns HttpMethod.GET
            every { path } returns REQUEST_PATH
            every { queryParams } returns MultiValueMapAdapter(mapOf(AppLoginUri.REDIRECT_TO to listOf("")))
        }

        expectException(
            { processor.process(exchange, processFun, defaultFun).orgContextWrite(ORGANIZATION).block() },
            "A redirection to the specified address not allowed."
        )

        verify { processFun wasNot Called }
        verify { defaultFun() wasNot Called }
    }

    @Test
    fun `null redirect query param is not processed`() {
        every { exchange.request } returns mockk {
            every { method } returns HttpMethod.GET
            every { path } returns REQUEST_PATH
            every { queryParams } returns MultiValueMapAdapter(mapOf(AppLoginUri.REDIRECT_TO to null))
        }

        expectException(
            { processor.process(exchange, processFun, defaultFun).block() },
            "Query param \"redirectTo\" not found"
        )

        verify { processFun wasNot Called }
        verify { defaultFun() wasNot Called }
    }

    private fun ServerHttpRequest.mockUri(
        host: String = "localhost",
        port: Int = 8443,
        path: String = "${AppLoginUri.PATH}/",
    ) {
        every { uri } returns URI(
            null,
            null,
            host,
            port,
            path,
            null,
            null
        )
    }

    private fun expectException(testedBlock: () -> Void?, exceptionMessage: String) {
        expectCatching { testedBlock.invoke() }
            .isFailure()
            .isA<AppLoginException>()
            .get {
                expectThat(message).isEqualTo(exceptionMessage)
            }
    }

    companion object {
        private val REQUEST_PATH = RequestPath.parse(AppLoginUri.PATH, "/")
        private const val GLOBAL_ALLOWED_URI = "https://localhost:8443"

        private const val ORGANIZATION_ALLOWED_URI = "https://some.host.com"
        private const val ORGANIZATION_ALLOWED_URI2 = "http://domain.cz:1234"

        private val ALLOWED_ORIGINS = listOf(ORGANIZATION_ALLOWED_URI, ORGANIZATION_ALLOWED_URI2)
        private val ORGANIZATION = Organization(
            id = "organizationId",
            allowedOrigins = ALLOWED_ORIGINS
        )

        @JvmStatic
        fun hosts() = ALLOWED_ORIGINS + GLOBAL_ALLOWED_URI
    }
}
