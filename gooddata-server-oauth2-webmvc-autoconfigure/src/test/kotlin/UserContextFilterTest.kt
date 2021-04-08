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
import com.gooddata.oauth2.server.common.UserContextAuthenticationToken
import io.mockk.called
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.authentication.logout.LogoutHandler
import java.time.Instant
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

internal class UserContextFilterTest {

    private val client: AuthenticationStoreClient = mockk()

    private val authenticationEntryPoint: AuthenticationEntryPoint = mockk()

    private val logoutHandler: LogoutHandler = mockk()

    private val userContextHolder: UserContextHolder = mockk()

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
        every { userContextHolder.setContext(any(), any(), any()) } returns Unit
        every { userContextHolder.clearContext() } returns Unit

        val filterChain = mockk<FilterChain> {
            every { doFilter(any(), any()) } returns Unit
        }

        SecurityContextHolder.setContext(context)
        UserContextFilter(client, authenticationEntryPoint, logoutHandler, userContextHolder)
            .doFilter(mockk<HttpServletRequest>(), mockk<HttpServletResponse>(), filterChain)
        SecurityContextHolder.clearContext()

        verify { logoutHandler wasNot called }
        verify { authenticationEntryPoint wasNot called }
        verify(exactly = 1) { filterChain.doFilter(any(), any()) }
        verify(exactly = 1) { userContextHolder.setContext("organizationId", "userId", "sub") }
        verify(exactly = 1) { userContextHolder.clearContext() }
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
        every { logoutHandler.logout(any(), any(), any()) } returns Unit
        every { authenticationEntryPoint.commence(any(), any(), any()) } returns Unit
        coEvery { client.getOrganizationByHostname("hostname") } returns Organization("organizationId")
        coEvery { client.getUserByAuthenticationId("organizationId", "sub") } returns User(
            "userId",
            lastLogoutAllTimestamp = Instant.ofEpochSecond(1),
        )

        val filterChain = mockk<FilterChain>()

        SecurityContextHolder.setContext(context)
        UserContextFilter(client, authenticationEntryPoint, logoutHandler, userContextHolder)
            .doFilter(mockk<HttpServletRequest>(), mockk<HttpServletResponse>(), filterChain)
        SecurityContextHolder.clearContext()

        verify(exactly = 1) { logoutHandler.logout(any(), any(), any()) }
        verify(exactly = 1) { authenticationEntryPoint.commence(any(), any(), any()) }
        verify { filterChain wasNot called }
        verify { userContextHolder wasNot called }
    }

    @Test
    fun `bearer context is stored`() {
        every { userContextHolder.setContext(any(), any(), any()) } returns Unit
        every { userContextHolder.clearContext() } returns Unit

        val context = SecurityContextImpl(
            UserContextAuthenticationToken(
                Organization("organizationId"),
                User("userId"),
            )
        )

        val filterChain = mockk<FilterChain> {
            every { doFilter(any(), any()) } returns Unit
        }

        SecurityContextHolder.setContext(context)
        UserContextFilter(client, authenticationEntryPoint, logoutHandler, userContextHolder)
            .doFilter(mockk<HttpServletRequest>(), mockk<HttpServletResponse>(), filterChain)
        SecurityContextHolder.clearContext()

        verify(exactly = 1) { filterChain.doFilter(any(), any()) }
        verify(exactly = 1) { userContextHolder.setContext("organizationId", "userId", null) }
        verify(exactly = 1) { userContextHolder.clearContext() }
    }
}
