/*
 * Copyright 2002-2020 the original author or authors.
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
 *
 * Forked from https://github.com/spring-projects/spring-security/blob/5.4.0/web/src/main/java/org/springframework/security/web/server/savedrequest/CookieServerRequestCache.java
 */
package com.gooddata.oauth2.server

import java.net.URI
import org.springframework.http.HttpMethod
import org.springframework.security.web.server.savedrequest.ServerRequestCache
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

/**
 * An implementation of [ServerRequestCache] that saves the requested URI in a cookie.
 *
 * @author Eleftheria Stein
 * @author Mathieu Ouellet
 * @since 5.4
 */
class CookieServerRequestCache(private val cookieService: ReactiveCookieService) : ServerRequestCache {
    private var saveRequestMatcher = ServerWebExchangeMatchers.pathMatchers(HttpMethod.GET, "/**")

    override fun saveRequest(exchange: ServerWebExchange): Mono<Void> =
        saveRequestMatcher.matches(exchange)
            .filter { it.isMatch }
            .flatMap {
                val path = exchange.request.path.pathWithinApplication().value()
                val query = exchange.request.uri.rawQuery
                val redirectUri = path + if (query != null) "?$query" else ""
                cookieService.createCookie(exchange, SPRING_REDIRECT_URI, redirectUri)
            }

    override fun getRedirectUri(exchange: ServerWebExchange): Mono<URI> =
        Mono.just(exchange)
            .flatMap { cookieService.decodeCookie(it, SPRING_REDIRECT_URI) }
            .map { URI.create(it) }
            .doOnNext { cookieService.invalidateCookie(exchange, SPRING_REDIRECT_URI) }

    override fun removeMatchingRequest(exchange: ServerWebExchange) = Mono.just(exchange.request)
}
