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

import com.gooddata.oauth2.server.OrganizationWebFilter.Companion.orgContextWrite
import com.nimbusds.jwt.JWTClaimNames
import com.nimbusds.openid.connect.sdk.claims.UserInfo
import io.mockk.InternalPlatformDsl.toStr
import io.mockk.called
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.springframework.http.HttpHeaders
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
import java.net.URI
import java.time.Instant
import java.util.stream.Stream

class JwtAuthenticationProcessorTest {

    private val client: AuthenticationStoreClient = mockk()

    private val authenticationEntryPoint: ServerAuthenticationEntryPoint = mockk()
    private val serverLogoutHandler: ServerLogoutHandler = mockk()
    private val userContextProvider: ReactorUserContextProvider = mockk()

    private val jwtAuthenticationProcessor =
        JwtAuthenticationProcessor(client, serverLogoutHandler, userContextProvider)

    private val jwt = prepareJwt()
    private val authenticationToken = JwtAuthenticationToken(jwt, emptyList(), "sub")

    private val webExchange = mockk<ServerWebExchange>() {
        every { request } returns mockk<ServerHttpRequest>() {
            every { uri } returns URI("https://hostname")
            every { headers } returns mockk<HttpHeaders>() {
                every { getFirst(HttpHeaders.AUTHORIZATION) }.returns("Bearer $TOKEN")
            }
        }
    }

    private val webFilterChain = mockk<WebFilterChain> {
        every { filter(any()) } returns Mono.empty()
    }

    @Test
    fun `user context is stored for jwt authentication`() {
        mockUserById(client, ORGANIZATION_ID, USER_ID)
        mockValidJwt()
        coEvery { userContextProvider.getContextView(any(), any(), any(), any(), any()) } returns Context.empty()

        jwtAuthenticationProcessor.authenticate(authenticationToken, webExchange, webFilterChain)
            .orgContextWrite(ORGANIZATION)
            .block()

        verify { serverLogoutHandler wasNot called }
        verify { authenticationEntryPoint wasNot called }
        verify(exactly = 1) { webFilterChain.filter(any()) }
        coVerify(exactly = 1) {
            userContextProvider.getContextView(
                ORGANIZATION_ID,
                USER_ID,
                "sub|123",
                null,
                AuthMethod.JWT
            )
        }
    }

    @Test
    fun `user context is stored for jwt without ID claim authentication`() {
        val jwt = prepareJwt(
            claims = mapOf(
                UserInfo.NAME_CLAIM_NAME to "sub|123",
                IdTokenClaimNames.SUB to USER_ID,
                IdTokenClaimNames.IAT to Instant.EPOCH,
            )
        )
        val authenticationToken = JwtAuthenticationToken(jwt, emptyList(), "sub")

        mockUserById(client, ORGANIZATION_ID, USER_ID)
        mockValidJwt(token = null.toStr())
        coEvery { userContextProvider.getContextView(any(), any(), any(), any(), any()) } returns Context.empty()

        jwtAuthenticationProcessor.authenticate(authenticationToken, webExchange, webFilterChain)
            .orgContextWrite(ORGANIZATION)
            .block()

        verify { serverLogoutHandler wasNot called }
        verify { authenticationEntryPoint wasNot called }
        verify(exactly = 1) { webFilterChain.filter(any()) }
        coVerify(exactly = 1) {
            userContextProvider.getContextView(
                ORGANIZATION_ID,
                USER_ID,
                "sub|123",
                any(),
                AuthMethod.JWT
            )
        }
    }

    @Test
    fun `user context is not processed when logoutAll has been triggered`() {
        every { serverLogoutHandler.logout(any(), any()) } returns Mono.empty()
        mockValidJwt()
        mockUserById(
            client,
            ORGANIZATION_ID,
            USER_ID,
            User(
                id = "userId",
                lastLogoutAllTimestamp = Instant.ofEpochSecond(1),
            )
        )

        expectThrows<JwtDisabledException> {
            jwtAuthenticationProcessor.authenticate(authenticationToken, webExchange, webFilterChain)
                .orgContextWrite(ORGANIZATION)
                .block()
        }.and {
            get { message }.isEqualTo("The JWT is disabled by logout / logout all.")
        }

        verify(exactly = 1) { serverLogoutHandler.logout(any(), any()) }
        verify { webFilterChain wasNot called }
        verify { userContextProvider wasNot called }
    }

    @Test
    fun `user context is not processed when invalidated jwt is used`() {
        every { serverLogoutHandler.logout(any(), any()) } returns Mono.empty()
        mockValidJwt(valid = false)

        expectThrows<JwtDisabledException> {
            jwtAuthenticationProcessor.authenticate(authenticationToken, webExchange, webFilterChain)
                .orgContextWrite(ORGANIZATION)
                .block()
        }.and {
            get { message }.isEqualTo("The JWT is disabled by logout / logout all.")
        }
        verify { webFilterChain wasNot called }
        verify { userContextProvider wasNot called }
    }

    @ParameterizedTest
    @MethodSource("usernames")
    fun `user context has resolved user name`(
        claimName: String?,
        userName: String?,
        resolvedName: String,
    ) {
        mockUserById(client, ORGANIZATION_ID, USER_ID, User(id = USER_ID, name = userName))
        mockValidJwt()
        coEvery { userContextProvider.getContextView(any(), any(), any(), any(), any()) } returns Context.empty()

        val claims = if (claimName == null) {
            mapOf(
                IdTokenClaimNames.SUB to USER_ID,
                JWTClaimNames.JWT_ID to TOKEN_ID,
                IdTokenClaimNames.IAT to Instant.EPOCH,
            )
        } else {
            mapOf(
                UserInfo.NAME_CLAIM_NAME to claimName,
                IdTokenClaimNames.SUB to USER_ID,
                JWTClaimNames.JWT_ID to TOKEN_ID,
                IdTokenClaimNames.IAT to Instant.EPOCH,
            )
        }

        val jwt = prepareJwt(claims = claims)
        val authenticationToken = JwtAuthenticationToken(jwt, emptyList(), "sub")

        jwtAuthenticationProcessor.authenticate(authenticationToken, webExchange, webFilterChain)
            .orgContextWrite(ORGANIZATION)
            .block()

        verify { serverLogoutHandler wasNot called }
        verify { authenticationEntryPoint wasNot called }
        verify(exactly = 1) { webFilterChain.filter(any()) }
        coVerify(exactly = 1) {
            userContextProvider.getContextView(
                ORGANIZATION_ID,
                USER_ID,
                resolvedName,
                null,
                AuthMethod.JWT
            )
        }
    }

    private fun mockValidJwt(token: String = TOKEN_ID, valid: Boolean = true) {
        every { client.isValidJwt(ORGANIZATION_ID, USER_ID, TOKEN_MD5_HASH, token) } returns Mono.just(valid)
    }

    private fun prepareJwt(
        tokenValue: String = "tokenValue",
        issuedAt: Instant = Instant.parse("2023-02-18T10:15:30.00Z"),
        expireAt: Instant = Instant.parse("2023-02-28T10:15:30.00Z"),
        headers: Map<String, Any> = mapOf(JoseHeaderNames.ALG to "RS256"),
        claims: Map<String, Any> = mapOf(
            UserInfo.NAME_CLAIM_NAME to "sub|123",
            IdTokenClaimNames.SUB to USER_ID,
            JWTClaimNames.JWT_ID to TOKEN_ID,
            IdTokenClaimNames.IAT to Instant.EPOCH,
        ),
    ) = Jwt(tokenValue, issuedAt, expireAt, headers, claims)
    companion object {
        private const val TOKEN = "token"
        private const val TOKEN_MD5_HASH = "6128148bc7c7abd76b32789d4962f7e4"
        private const val USER_ID = "sub"
        private const val ORGANIZATION_ID = "organizationId"
        private const val TOKEN_ID = "tokenId"
        private val ORGANIZATION = Organization(ORGANIZATION_ID)

        @JvmStatic
        fun usernames() = Stream.of(
            Arguments.of(
                null,
                null,
                USER_ID,
            ),
            Arguments.of(
                "John Doe",
                null,
                "John Doe",
            ),
            Arguments.of(
                null,
                "Karel Novak",
                "Karel Novak",
            ),
            Arguments.of(
                "John Doe",
                "Karel Novak",
                "John Doe",
            ),
        )
    }
}
