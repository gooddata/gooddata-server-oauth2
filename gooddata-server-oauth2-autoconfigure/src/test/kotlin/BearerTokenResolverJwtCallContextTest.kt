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
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken
import org.springframework.web.server.ServerWebExchange
import strikt.api.expectThat
import strikt.assertions.isA
import strikt.assertions.isNull
import strikt.assertions.isNotNull
import java.net.InetSocketAddress

internal class BearerTokenResolverJwtCallContextTest {

    private val client: AuthenticationStoreClient = mockk()
    private val auditClient: AuthenticationAuditClient = mockk()

    @Test
    fun `resolve returns no-op manager when call context has authMethod=JWT`() {
        val mockExchange: ServerWebExchange = mockk {
            every { request.headers.getFirst("gd-call-context") } returns
                """{"authMethod":"JWT","userId":"u1","orgId":"org1"}"""
            every { request.remoteAddress } returns InetSocketAddress("127.0.0.1", 8080)
        }

        val resolver = BearerTokenReactiveAuthenticationManagerResolver(client, auditClient)
        val manager = resolver.resolve(mockExchange).block()!!

        val token = BearerTokenAuthenticationToken("some.jwt.token")
        val result = manager.authenticate(token).block()

        expectThat(result).isNull()
    }

    @Test
    fun `resolve returns non-null manager when call context header is absent`() {
        val mockExchange: ServerWebExchange = mockk {
            every { request.headers.getFirst("gd-call-context") } returns null
            every { request.remoteAddress } returns InetSocketAddress("127.0.0.1", 8080)
        }

        val resolver = BearerTokenReactiveAuthenticationManagerResolver(client, auditClient)
        val manager = resolver.resolve(mockExchange).block()

        expectThat(manager).isNotNull()
    }

    @Test
    fun `resolve returns non-null manager when call context has different authMethod`() {
        val mockExchange: ServerWebExchange = mockk {
            every { request.headers.getFirst("gd-call-context") } returns
                """{"authMethod":"API_TOKEN","userId":"u1","orgId":"org1"}"""
            every { request.remoteAddress } returns InetSocketAddress("127.0.0.1", 8080)
        }

        val resolver = BearerTokenReactiveAuthenticationManagerResolver(client, auditClient)
        val manager = resolver.resolve(mockExchange).block()

        expectThat(manager).isNotNull()
    }
}
