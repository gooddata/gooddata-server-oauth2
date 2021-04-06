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

import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.DefaultRedirectStrategy
import org.springframework.security.web.savedrequest.RequestCache
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * [AuthenticationEntryPoint] handles `XMLHttpRequest` are first redirected to `/appLogin` URI with `401 Unauthorized`
 * to allow JS apps to properly handle browser redirects. All other requests are redirected directly to
 * `/oauth2/authorization/{hostname}` using `302 Found` status code and `Location` header. It generates dynamic
 * redirects based on request's `Host` header as individual Auth2 providers are not defined statically during
 * Spring Context bootstrap.
 */
class HostBasedAuthenticationEntryPoint(
    private val requestCache: RequestCache,
) : AuthenticationEntryPoint {
    private val redirectStrategy = DefaultRedirectStrategy()
    private val xmlHttpRequestRedirectStrategy = XMLHttpRequestRedirectStrategy()

    override fun commence(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authException: AuthenticationException?
    ) {
        if (request.getHeader("X-Requested-With") == "XMLHttpRequest") {
            xmlHttpRequestRedirectStrategy.sendRedirect(request, response, "/appLogin")
        } else {
            val url = "/oauth2/authorization/${request.serverName}"
            requestCache.saveRequest(request, response)
            redirectStrategy.sendRedirect(request, response, url)
        }
    }
}
