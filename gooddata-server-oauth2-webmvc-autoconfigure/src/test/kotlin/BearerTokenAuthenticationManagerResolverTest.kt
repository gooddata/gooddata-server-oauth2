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
package com.gooddata.oauth2.server.servlet

import com.gooddata.oauth2.server.common.AuthenticationStoreClient
import com.gooddata.oauth2.server.common.Organization
import com.gooddata.oauth2.server.common.User
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Test
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException
import strikt.api.expectThat
import strikt.api.expectThrows
import strikt.assertions.isNull
import strikt.assertions.isTrue
import javax.servlet.http.HttpServletRequest

internal class BearerTokenAuthenticationManagerResolverTest {

    private val client: AuthenticationStoreClient = mockk()

    @Test
    fun `authenticates incorrect token type`() {
        val resolver = BearerTokenAuthenticationManagerResolver(client)
        val manager = resolver.resolve(mockk())

        expectThat(manager.authenticate(mockk<OAuth2AuthenticationToken>())) {
            isNull()
        }
    }

    @Test
    fun `authenticates incorrect bearer token`() {
        val request: HttpServletRequest = mockk {
            every { serverName } returns "localhost"
        }
        coEvery { client.getOrganizationByHostname("localhost") } returns Organization("organizationId")
        coEvery { client.getUserByApiToken("organizationId", "invalid") } throws
            InvalidBearerTokenException("")
        val resolver = BearerTokenAuthenticationManagerResolver(client)
        val manager = resolver.resolve(request)

        expectThrows<InvalidBearerTokenException> {
            manager.authenticate(BearerTokenAuthenticationToken("invalid"))
        }
    }

    @Test
    fun `authenticates valid bearer token`() {
        val request: HttpServletRequest = mockk {
            every { serverName } returns "localhost"
        }
        coEvery { client.getOrganizationByHostname("localhost") } returns Organization("organizationId")
        coEvery { client.getUserByApiToken("organizationId", "supersecuretoken") } returns User(
            "userId",
        )

        val resolver = BearerTokenAuthenticationManagerResolver(client)
        val manager = resolver.resolve(request)

        val authenticated = manager.authenticate(BearerTokenAuthenticationToken("supersecuretoken"))
        expectThat(authenticated) {
            get(Authentication::isAuthenticated).isTrue()
        }
    }
}
