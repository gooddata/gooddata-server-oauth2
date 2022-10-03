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
package com.gooddata.oauth2.server

import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.security.web.server.savedrequest.ServerRequestCache
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.net.URI

/**
 * Delegates multiple [ServerRequestCache] writing/reading strategies.
 *
 * @param cookieServerRequestCache the default [CookieServerRequestCache] strategy
 * @param appLoginRequestCacheWriter the strategy for writing "appLogin" info into the request cache
 * @param appLoginRedirectProcessor the "appLogin" [AppLoginUri.REDIRECT_TO] processor
 */
class DelegatingServerRequestCache(
    private val cookieServerRequestCache: CookieServerRequestCache,
    private val appLoginRequestCacheWriter: AppLoginCookieRequestCacheWriter,
    private val appLoginRedirectProcessor: AppLoginRedirectProcessor,
) : ServerRequestCache {

    override fun saveRequest(exchange: ServerWebExchange): Mono<Void> =
        appLoginRedirectProcessor.process(
            exchange,
            // The redirectUri represents the absolute or relative URL, where the successful authentication should be
            // redirected to. Therefore, the original preprocessing done in the CookieServerRequestCache#saveRequest
            // function is omitted
            { redirectUri ->
                appLoginRequestCacheWriter.saveRequest(exchange, redirectUri)
                Mono.empty()
            },
            { cookieServerRequestCache.saveRequest(exchange) }
        )

    override fun getRedirectUri(exchange: ServerWebExchange): Mono<URI> =
        cookieServerRequestCache.getRedirectUri(exchange)

    override fun removeMatchingRequest(exchange: ServerWebExchange): Mono<ServerHttpRequest> =
        cookieServerRequestCache.removeMatchingRequest(exchange)
}
