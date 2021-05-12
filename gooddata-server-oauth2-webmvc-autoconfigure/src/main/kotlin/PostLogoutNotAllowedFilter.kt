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
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.web.filter.OncePerRequestFilter
import org.springframework.web.server.ResponseStatusException
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * Filter that POST on /logout resource results in 405 METHOD_NOT_ALLOWED.
 */
class PostLogoutNotAllowedFilter : OncePerRequestFilter() {

    private val postLogoutMatcher = AntPathRequestMatcher("/logout", "POST")

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        if (postLogoutMatcher.matches(request)) {
            throw ResponseStatusException(
                HttpStatus.METHOD_NOT_ALLOWED,
                "POST method is not allowed on ${request.pathInfo}"
            )
        } else {
            filterChain.doFilter(request, response)
        }
    }
}
