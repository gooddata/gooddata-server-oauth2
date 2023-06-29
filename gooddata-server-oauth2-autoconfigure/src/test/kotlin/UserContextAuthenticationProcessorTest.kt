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
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono
import reactor.util.context.Context

class UserContextAuthenticationProcessorTest {

    private val userContextProvider: ReactorUserContextProvider = mockk()

    private val userContextAuthenticationProcessor = UserContextAuthenticationProcessor(userContextProvider)

    @Test
    fun `bearer context is stored`() {
        coEvery { userContextProvider.getContextView(any(), any(), any()) } returns Context.empty()

        val authenticationToken = UserContextAuthenticationToken(
            Organization("organizationId"),
            User("userId"),
        )

        val webFilterChain = mockk<WebFilterChain> {
            every { filter(any()) } returns Mono.empty()
        }

        userContextAuthenticationProcessor.authenticate(authenticationToken, mockk(), webFilterChain).block()

        verify(exactly = 1) { webFilterChain.filter(any()) }
        coVerify(exactly = 1) { userContextProvider.getContextView("organizationId", "userId", null) }
    }
}
