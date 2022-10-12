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

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.reactor.mono
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers
import org.springframework.web.server.ResponseStatusException
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono

/**
 * Filter that POST on /logout resource results in 405 METHOD_NOT_ALLOWED.
 */
class PostLogoutNotAllowedWebFilter : WebFilter {

    private val postLogoutMatcher = ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, "/logout", "/logout/all")

    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> = mono(Dispatchers.Unconfined) {
        postLogoutMatcher.matches(exchange)
            .awaitOrNull()
            ?.takeIf { it.isMatch }
            ?.let {
                throw ResponseStatusException(
                    HttpStatus.METHOD_NOT_ALLOWED,
                    "POST method is not allowed on ${exchange.request.path}"
                )
            }
            ?: chain.filter(exchange).then(Mono.empty<Void>()).awaitOrNull()
    }
}
