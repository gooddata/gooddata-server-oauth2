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

import org.springframework.http.HttpStatus
import org.springframework.security.web.DefaultRedirectStrategy
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * [org.springframework.security.web.RedirectStrategy] that uses `401 Unauthorized` instead of `302 Found`
 * and that sends redirect URI in response body instead of `Location` header.
 */
class XMLHttpRequestRedirectStrategy : DefaultRedirectStrategy() {
    override fun sendRedirect(request: HttpServletRequest, response: HttpServletResponse, url: String?) {
        val redirectUrl = response.encodeRedirectURL(calculateRedirectUrl(request.contextPath, url))
        response.status = HttpStatus.UNAUTHORIZED.value()
        response.writer.write(redirectUrl)
    }
}
