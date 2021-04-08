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
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.web.savedrequest.RequestCache
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

internal class HostBasedAuthenticationEntryPointTest {

    private val request: HttpServletRequest = mockk()

    private val response: HttpServletResponse = mockk()

    private val requestCache: RequestCache = mockk()

    private val entryPoint = HostBasedAuthenticationEntryPoint(requestCache)

    @Test
    fun `sends redirect`() {
        every { request.serverName } returns "host"
        every { request.contextPath } returns ""
        every { request.getHeader(any()) } returns null
        every { response.encodeRedirectURL(any()) } returns "/oauth2/authorization/host"
        every { response.sendRedirect(any()) } returns Unit
        every { requestCache.saveRequest(any(), any()) } returns Unit

        entryPoint.commence(request, response, BadCredentialsException("msg"))

        verify(exactly = 1) { response.encodeRedirectURL("/oauth2/authorization/host") }
        verify(exactly = 1) { response.sendRedirect("/oauth2/authorization/host") }
    }

    @Test
    fun `sends unauthorized for XMLHttpRequest`() {
        every { request.serverName } returns "host"
        every { request.contextPath } returns ""
        every { request.getHeader("X-Requested-With") } returns "XMLHttpRequest"
        every { response.encodeRedirectURL(any()) } returns "/appLogin"
        every { response.sendRedirect(any()) } returns Unit
        every { response.status = any() } returns Unit
        every { response.writer.write(any<String>()) } returns Unit
        every { requestCache.saveRequest(any(), any()) } returns Unit

        entryPoint.commence(request, response, BadCredentialsException("msg"))

        verify(exactly = 1) { response.encodeRedirectURL("/appLogin") }
        verify(exactly = 1) { response.status = HttpStatus.UNAUTHORIZED.value() }
        verify(exactly = 1) { response.writer.write("/appLogin") }
    }
}
