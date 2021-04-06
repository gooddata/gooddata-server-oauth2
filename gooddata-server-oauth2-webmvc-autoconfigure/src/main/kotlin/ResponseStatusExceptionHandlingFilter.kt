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

import org.springframework.web.filter.OncePerRequestFilter
import org.springframework.web.server.ResponseStatusException
import org.springframework.web.servlet.mvc.annotation.ResponseStatusExceptionResolver
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * [javax.servlet.Filter] responsible for handling [ResponseStatusException] thrown up by filter chain.
 *
 * This is necessary as [ResponseStatusException] is automagically handled only when thrown from controllers. In filters
 * the status code is ignored and 500 status code is used instead.
 */
class ResponseStatusExceptionHandlingFilter : OncePerRequestFilter() {

    private val resolver = ResponseStatusExceptionResolver()

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        try {
            filterChain.doFilter(request, response)
        } catch (e: ResponseStatusException) {
            resolver.resolveException(request, response, null, e)
        }
    }
}
