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
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.springframework.http.HttpStatus
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class XMLHttpRequestRedirectStrategyTest {

    private val request: HttpServletRequest = mockk()

    private val response: HttpServletResponse = mockk()

    private val strategy = XMLHttpRequestRedirectStrategy()

    @Test
    fun `sends 401 Unauthorized with location in body`() {
        every { request.contextPath } returns ""
        every { response.encodeRedirectURL(any()) } returns "/location"
        every { response.sendRedirect(any()) } returns Unit
        every { response.status = any() } returns Unit
        every { response.writer.write(any<String>()) } returns Unit

        strategy.sendRedirect(request, response, "/location")

        verify(exactly = 1) { response.encodeRedirectURL("/location") }
        verify(exactly = 1) { response.status = HttpStatus.UNAUTHORIZED.value() }
        verify(exactly = 1) { response.writer.write("/location") }
    }
}
