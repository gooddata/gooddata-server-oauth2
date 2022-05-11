/*
 * Copyright 2022 GoodData Corporation
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
package com.gooddata.oauth2.server.reactive

import org.springframework.http.HttpMethod
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

/**
 * Match HTTP request against expected protocol and regex path pattern
 *
 * @param path expected regex path pattern
 * @param method expected HTTP method
 */
class RegexServerWebExchangeMatcher(
    private val path: Regex,
    private val method: HttpMethod
) : ServerWebExchangeMatcher {

    override fun matches(serverWebExchange: ServerWebExchange): Mono<ServerWebExchangeMatcher.MatchResult> =
        serverWebExchange.request.let { request ->
            if (matches(request.method, request.path.toString())) {
                ServerWebExchangeMatcher.MatchResult.match()
            } else {
                ServerWebExchangeMatcher.MatchResult.notMatch()
            }
        }

    fun matches(method: HttpMethod?, path: String): Boolean =
        this.method == method && this.path.containsMatchIn(path)
}
