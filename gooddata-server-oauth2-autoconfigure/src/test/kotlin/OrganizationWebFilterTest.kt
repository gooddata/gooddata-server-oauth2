/*
 * Copyright 2023 GoodData Corporation
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

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.web.server.ResponseStatusException
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono
import strikt.api.expectThrows
import strikt.assertions.isEqualTo
import java.net.URI

internal class OrganizationWebFilterTest {

    private val client = mockk<AuthenticationStoreClient>()
    private val exchange = mockk<ServerWebExchange>(relaxed = true) {
        every { request } returns mockk {
            every { uri } returns URI("https://$HOST")
        }
        every { response } returns mockk {
            every { setStatusCode(any()) } returns true
            every { headers } returns HttpHeaders()
        }
    }
    private val chain = mockk<WebFilterChain> {
        every { filter(any()) } returns Mono.empty()
    }
    private val webFilter = OrganizationWebFilter(client)

    @Test
    fun `org is found and stored in context`() {
        val organization = Organization("org")
        mockOrganization(client, HOST, organization)

        webFilter
            .filter(exchange, chain)
            .contextWrite { it.put(OrganizationContext::class, OrganizationContext(organization)) }
            .block()

        coVerify(exactly = 1) { client.getOrganizationByHostname(HOST) }
        verify(exactly = 1) { chain.filter(exchange) }
    }

    @Test
    fun `org does not exists in the context`() {
        mockOrganizationError(client, HOST, ResponseStatusException(HttpStatus.NOT_FOUND))

        val response = webFilter.filter(exchange, chain)

        expectThrows<ResponseStatusException> {
            response.awaitOrNull()
        }.get { status }.isEqualTo(HttpStatus.NOT_FOUND)
    }

    companion object {
        private const val HOST = "localhost"
    }
}
