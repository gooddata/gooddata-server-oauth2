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

import com.nimbusds.openid.connect.sdk.claims.UserInfo
import io.mockk.called
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import java.net.URI
import java.time.Instant
import org.junit.jupiter.api.Test
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.jwt.JoseHeaderNames
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.security.web.server.ServerAuthenticationEntryPoint
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono
import reactor.util.context.Context
import strikt.api.expectThrows
import strikt.assertions.isEqualTo

class JwtAuthenticationProcessorTest {

    private val client: AuthenticationStoreClient = mockk()
    private val authenticationEntryPoint: ServerAuthenticationEntryPoint = mockk()
    private val serverLogoutHandler: ServerLogoutHandler = mockk()
    private val userContextProvider: ReactorUserContextProvider = mockk()

    private val jwtAuthenticationProcessor =
        JwtAuthenticationProcessor(client, serverLogoutHandler, userContextProvider)

    @Test
    fun `user context is stored for jwt authentication`() {
        val jwt = Jwt(
            "tokenValue",
            Instant.parse("2023-02-18T10:15:30.00Z"),
            Instant.parse("2023-02-28T10:15:30.00Z"),
            mapOf(
                JoseHeaderNames.ALG to "RS256"
            ),
            mapOf(
                UserInfo.NAME_CLAIM_NAME to "sub|123",
                IdTokenClaimNames.SUB to "sub",
                IdTokenClaimNames.IAT to Instant.EPOCH,
            ),
        )

        val authenticationToken = JwtAuthenticationToken(jwt, emptyList(), "sub")

        val webExchange = mockk<ServerWebExchange> {
            every { request } returns mockk<ServerHttpRequest>() {
                every { uri } returns URI("https://hostname")
            }
        }

        coEvery { client.getOrganizationByHostname("hostname") } returns Organization("organizationId")
        coEvery { client.getUserById("organizationId", "sub") } returns User("sub")
        coEvery { userContextProvider.getContextView(any(), any(), any()) } returns Context.empty()

        val webFilterChain = mockk<WebFilterChain> {
            every { filter(any()) } returns Mono.empty()
        }
        jwtAuthenticationProcessor.authenticate(authenticationToken, webExchange, webFilterChain).block()

        verify { serverLogoutHandler wasNot called }
        verify { authenticationEntryPoint wasNot called }
        verify(exactly = 1) { webFilterChain.filter(any()) }
        coVerify(exactly = 1) { userContextProvider.getContextView("organizationId", "sub", "sub|123") }
    }

    @Test
    fun `user context is not processed when logoutAll has been triggered`() {
        val jwt = Jwt(
            "tokenValue",
            Instant.parse("2023-02-18T10:15:30.00Z"),
            Instant.parse("2023-02-28T10:15:30.00Z"),
            mapOf(
                JoseHeaderNames.ALG to "RS256"
            ),
            mapOf(
                UserInfo.NAME_CLAIM_NAME to "sub|123",
                IdTokenClaimNames.SUB to "sub",
                IdTokenClaimNames.IAT to Instant.EPOCH,
            ),
        )

        val authenticationToken = JwtAuthenticationToken(
            jwt,
            emptyList(),
            "sub"
        )

        val webExchange = mockk<ServerWebExchange>() {
            every { request } returns mockk<ServerHttpRequest>() {
                every { uri } returns URI("https://hostname")
            }
        }

        every { serverLogoutHandler.logout(any(), any()) } returns Mono.empty()
        coEvery { client.getOrganizationByHostname("hostname") } returns Organization("organizationId")
        coEvery { client.getUserById("organizationId", "sub") } returns User(
            "userId",
            lastLogoutAllTimestamp = Instant.ofEpochSecond(1),
        )

        val webFilterChain = mockk<WebFilterChain> {
            every { filter(any()) } returns Mono.empty()
        }

        expectThrows<JWTDisabledException> {
            jwtAuthenticationProcessor.authenticate(authenticationToken, webExchange, webFilterChain).block()
        }.and {
            get { message }.isEqualTo("The JWT is disabled by logout / logout all.")
        }

        verify(exactly = 1) { serverLogoutHandler.logout(any(), any()) }
        verify { webFilterChain wasNot called }
        verify { userContextProvider wasNot called }
    }
}
