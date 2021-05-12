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

import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Test
import org.springframework.http.HttpStatus
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.web.server.ResponseStatusException
import strikt.api.expectThrows
import strikt.assertions.isEqualTo
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletResponse

internal class PostLogoutNotAllowedFilterTest {

    @Test
    fun `POST logout is processed`() {
        val filterChain = mockk<FilterChain> {
            every { doFilter(any(), any()) } returns Unit
        }

        val request = MockHttpServletRequest("POST", "/logout").apply {
            pathInfo = "/logout"
        }

        expectThrows<ResponseStatusException> {
            PostLogoutNotAllowedFilter().doFilter(request, mockk<HttpServletResponse>(), filterChain)
        }.get { status }.isEqualTo(HttpStatus.METHOD_NOT_ALLOWED)
    }

    @Test
    fun `GET logout is ignored`() {
        val filterChain = mockk<FilterChain> {
            every { doFilter(any(), any()) } returns Unit
        }

        val request = MockHttpServletRequest("GET", "/logout").apply {
            pathInfo = "/logout"
        }

        PostLogoutNotAllowedFilter().doFilter(request, mockk<HttpServletResponse>(), filterChain)
    }
}
