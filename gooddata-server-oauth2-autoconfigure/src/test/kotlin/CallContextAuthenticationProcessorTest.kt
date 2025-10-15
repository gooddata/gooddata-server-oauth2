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

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono.empty
import reactor.test.StepVerifier
import reactor.util.context.Context

class CallContextAuthenticationProcessorTest {

    private val headerProcessor: CallContextHeaderProcessor = mockk()
    private val userContextProvider: ReactorUserContextProvider = mockk()
    private val processor = CallContextAuthenticationProcessor(headerProcessor, userContextProvider)

    private val webExchange: ServerWebExchange = mockk(relaxed = true)
    private val webFilterChain: WebFilterChain = mockk {
        every { filter(any()) } returns empty()
    }

    @Test
    fun `successful authentication with all required fields`() {
        val authToken = CallContextAuthenticationToken("base64-encoded-header")
        val authDetails = CallContextAuth(
            organizationId = "org123",
            userId = "user456",
            authMethod = "API_TOKEN",
            tokenId = "token789"
        )

        every { headerProcessor.parseCallContextHeader("base64-encoded-header") } returns authDetails
        coEvery {
            userContextProvider.getContextView(any(), any(), any(), any(), any(), any())
        } returns Context.empty()

        processor.authenticate(authToken, webExchange, webFilterChain).block()

        verify(exactly = 1) { webFilterChain.filter(webExchange) }
        coVerify(exactly = 1) {
            userContextProvider.getContextView(
                organizationId = "org123",
                userId = "user456",
                userName = null,
                tokenId = "token789",
                authMethod = AuthMethod.API_TOKEN,
                accessToken = null
            )
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["API_TOKEN", "JWT", "OIDC", "NOT_APPLICABLE"])
    fun `successful authentication with different auth methods`(authMethodStr: String) {
        val authToken = CallContextAuthenticationToken("header-value")
        val authDetails = CallContextAuth(
            organizationId = "org123",
            userId = "user456",
            authMethod = authMethodStr
        )

        every { headerProcessor.parseCallContextHeader("header-value") } returns authDetails
        coEvery {
            userContextProvider.getContextView(any(), any(), any(), any(), any(), any())
        } returns Context.empty()

        processor.authenticate(authToken, webExchange, webFilterChain).block()

        verify(exactly = 1) { webFilterChain.filter(webExchange) }
        coVerify(exactly = 1) {
            userContextProvider.getContextView(
                organizationId = "org123",
                userId = "user456",
                userName = null,
                tokenId = null,
                authMethod = AuthMethod.valueOf(authMethodStr),
                accessToken = null
            )
        }
    }

    @Test
    fun `authentication without optional tokenId`() {
        val authToken = CallContextAuthenticationToken("header-value")
        val authDetails = CallContextAuth(
            organizationId = "org123",
            userId = "user456",
            authMethod = "JWT"
        )

        every { headerProcessor.parseCallContextHeader("header-value") } returns authDetails
        coEvery {
            userContextProvider.getContextView(any(), any(), any(), any(), any(), any())
        } returns Context.empty()

        processor.authenticate(authToken, webExchange, webFilterChain).block()

        coVerify(exactly = 1) {
            userContextProvider.getContextView(
                organizationId = "org123",
                userId = "user456",
                userName = null,
                tokenId = null,
                authMethod = AuthMethod.JWT,
                accessToken = null
            )
        }
    }

    @Test
    fun `null call context throws exception`() {
        val authToken = CallContextAuthenticationToken("header-value")

        every { headerProcessor.parseCallContextHeader("header-value") } returns null

        StepVerifier.create(processor.authenticate(authToken, webExchange, webFilterChain))
            .expectErrorMatches {
                it is CallContextAuthenticationException &&
                    it.message == "Call context header contains no user information"
            }
            .verify()

        verify(exactly = 0) { webFilterChain.filter(any()) }
    }

    @Test
    fun `invalid authMethod enum value throws exception`() {
        val authToken = CallContextAuthenticationToken("header-value")
        val authDetails = CallContextAuth(
            organizationId = "org123",
            userId = "user456",
            authMethod = "INVALID_METHOD"
        )

        every { headerProcessor.parseCallContextHeader("header-value") } returns authDetails

        StepVerifier.create(processor.authenticate(authToken, webExchange, webFilterChain))
            .expectErrorMatches {
                it is CallContextAuthenticationException &&
                    it.message == "Invalid authentication method in call context"
            }
            .verify()

        verify(exactly = 0) { webFilterChain.filter(any()) }
    }

    @Test
    fun `malformed header throws exception`() {
        val authToken = CallContextAuthenticationToken("malformed-header")

        every { headerProcessor.parseCallContextHeader("malformed-header") } throws
            IllegalStateException("Invalid format")

        StepVerifier.create(processor.authenticate(authToken, webExchange, webFilterChain))
            .expectErrorMatches {
                it is CallContextAuthenticationException &&
                    it.message == "Authentication failed" &&
                    it.cause is IllegalStateException
            }
            .verify()

        verify(exactly = 0) { webFilterChain.filter(any()) }
    }
}
