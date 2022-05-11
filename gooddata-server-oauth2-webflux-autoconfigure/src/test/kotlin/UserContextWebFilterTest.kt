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

import com.gooddata.oauth2.server.common.AuthenticationStoreClient
import com.gooddata.oauth2.server.common.Organization
import com.gooddata.oauth2.server.common.User
import com.gooddata.oauth2.server.common.UserContextAuthenticationToken
import io.mockk.called
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.reactor.ReactorContext
import org.junit.jupiter.api.Test
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority
import org.springframework.security.web.server.ServerAuthenticationEntryPoint
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono
import reactor.util.context.Context
import java.time.Instant

internal class UserContextWebFilterTest {

    private val client: AuthenticationStoreClient = mockk()

    private val authenticationEntryPoint: ServerAuthenticationEntryPoint = mockk()

    private val serverLogoutHandler: ServerLogoutHandler = mockk()

    private val userContextHolder: UserContextHolder<*> = mockk()

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `user context is stored`() {
        val idToken = OidcIdToken(
            "tokenValue",
            Instant.EPOCH,
            Instant.EPOCH.plusSeconds(1),
            mapOf(
                IdTokenClaimNames.SUB to "sub",
                IdTokenClaimNames.IAT to Instant.EPOCH
            )
        )
        val context = SecurityContextImpl(
            OAuth2AuthenticationToken(
                DefaultOidcUser(
                    listOf(OidcUserAuthority(idToken)),
                    idToken
                ),
                emptyList(),
                "hostname"
            )
        )
        coEvery { client.getOrganizationByHostname("hostname") } returns Organization("organizationId")
        coEvery { client.getUserByAuthenticationId("organizationId", "sub") } returns User(
            "userId",
        )
        coEvery { userContextHolder.setContext(any(), any(), any()) } returns ReactorContext(Context.empty())

        val webFilterChain = mockk<WebFilterChain> {
            every { filter(any()) } returns Mono.empty()
        }
        val filter = UserContextWebFilter(client, authenticationEntryPoint, serverLogoutHandler, userContextHolder)

        filter
            .filter(mockk(), webFilterChain)
            .contextWrite { it.put(SecurityContext::class.java, Mono.just(context)) }
            .block()

        verify { serverLogoutHandler wasNot called }
        verify { authenticationEntryPoint wasNot called }
        verify(exactly = 1) { webFilterChain.filter(any()) }
        coVerify(exactly = 1) { userContextHolder.setContext("organizationId", "userId", "sub") }
    }

    @Test
    fun `user context is not processed when logoutAll has been triggered`() {
        val idToken = OidcIdToken(
            "tokenValue",
            Instant.EPOCH,
            Instant.EPOCH.plusSeconds(1),
            mapOf(
                IdTokenClaimNames.SUB to "sub",
                IdTokenClaimNames.IAT to Instant.EPOCH
            )
        )
        val context = SecurityContextImpl(
            OAuth2AuthenticationToken(
                DefaultOidcUser(
                    listOf(OidcUserAuthority(idToken)),
                    idToken
                ),
                emptyList(),
                "hostname"
            )
        )
        every { serverLogoutHandler.logout(any(), any()) } returns Mono.empty()
        every { authenticationEntryPoint.commence(any(), any()) } returns Mono.empty()
        coEvery { client.getOrganizationByHostname("hostname") } returns Organization("organizationId")
        coEvery { client.getUserByAuthenticationId("organizationId", "sub") } returns User(
            "userId",
            lastLogoutAllTimestamp = Instant.ofEpochSecond(1),
        )

        val webFilterChain = mockk<WebFilterChain>()

        val filter = UserContextWebFilter(client, authenticationEntryPoint, serverLogoutHandler, userContextHolder)

        filter
            .filter(mockk(), webFilterChain)
            .contextWrite { it.put(SecurityContext::class.java, Mono.just(context)) }
            .block()

        verify(exactly = 1) { serverLogoutHandler.logout(any(), any()) }
        verify(exactly = 1) { authenticationEntryPoint.commence(any(), any()) }
        verify { webFilterChain wasNot called }
        verify { userContextHolder wasNot called }
    }

    @Test
    fun `bearer context is stored`() {
        coEvery { userContextHolder.setContext(any(), any(), any()) } returns ReactorContext(Context.empty())

        val context = SecurityContextImpl(
            UserContextAuthenticationToken(
                Organization("organizationId"),
                User("userId"),
            )
        )

        val webFilterChain = mockk<WebFilterChain> {
            every { filter(any()) } returns Mono.empty()
        }
        val filter = UserContextWebFilter(client, authenticationEntryPoint, serverLogoutHandler, userContextHolder)

        filter
            .filter(mockk(), webFilterChain)
            .contextWrite { it.put(SecurityContext::class.java, Mono.just(context)) }
            .block()

        verify(exactly = 1) { webFilterChain.filter(any()) }
        coVerify(exactly = 1) { userContextHolder.setContext("organizationId", "userId", null) }
    }
}
