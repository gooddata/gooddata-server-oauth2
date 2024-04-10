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
package com.gooddata.oauth2.server

import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono

internal class UserContextWebFilterTest {

    private val oidcAuthenticationProcessor: OidcAuthenticationProcessor = mockk()
    private val jwtAuthenticationProcessor: JwtAuthenticationProcessor = mockk()
    private val userContextAuthenticationProcessor: UserContextAuthenticationProcessor = mockk()
    private val filter = UserContextWebFilter(
        oidcAuthenticationProcessor,
        jwtAuthenticationProcessor,
        userContextAuthenticationProcessor
    )

    @Test
    fun `oidc authentication triggered`() {
        val authenticationToken = mockk<OAuth2AuthenticationToken>()
        val context = SecurityContextImpl(authenticationToken)
        val webFilterChain = mockk<WebFilterChain>()

        every {
            oidcAuthenticationProcessor.authenticate(
                authenticationToken,
                any(),
                webFilterChain
            )
        } returns Mono.empty()

        filter
            .filter(mockk(), webFilterChain)
            .contextWrite { it.put(SecurityContext::class.java, Mono.just(context)) }
            .block()

        verify(exactly = 1) { oidcAuthenticationProcessor.authenticate(authenticationToken, any(), webFilterChain) }
    }

    @Test
    fun `userContext authentication triggered`() {
        val authenticationToken = mockk<UserContextAuthenticationToken>()
        val context = SecurityContextImpl(authenticationToken)
        val webFilterChain = mockk<WebFilterChain>()

        every {
            userContextAuthenticationProcessor.authenticate(
                authenticationToken,
                any(),
                webFilterChain
            )
        } returns Mono.empty()

        filter
            .filter(mockk(), webFilterChain)
            .contextWrite { it.put(SecurityContext::class.java, Mono.just(context)) }
            .block()

        verify(exactly = 1) {
            userContextAuthenticationProcessor.authenticate(
                authenticationToken,
                any(),
                webFilterChain
            )
        }
    }

    @Test
    fun `jwt authentication triggered`() {
        val authenticationToken = mockk<JwtAuthenticationToken>()
        val context = SecurityContextImpl(authenticationToken)
        val webFilterChain = mockk<WebFilterChain>()

        every {
            jwtAuthenticationProcessor.authenticate(
                authenticationToken,
                any(),
                webFilterChain
            )
        } returns Mono.empty()

        filter
            .filter(mockk(), webFilterChain)
            .contextWrite { it.put(SecurityContext::class.java, Mono.just(context)) }
            .block()

        verify(exactly = 1) {
            jwtAuthenticationProcessor.authenticate(
                authenticationToken,
                any(),
                webFilterChain
            )
        }
    }

    @Test
    fun `unauthenticated resource trigger`() {
        val webFilterChain = mockk<WebFilterChain> {
            every { filter(any()) } returns Mono.empty()
        }
        val filter = UserContextWebFilter(
            oidcAuthenticationProcessor,
            jwtAuthenticationProcessor,
            userContextAuthenticationProcessor
        )

        filter
            .filter(mockk(), webFilterChain)
            .block()

        verify(exactly = 1) { webFilterChain.filter(any()) }
    }
}
