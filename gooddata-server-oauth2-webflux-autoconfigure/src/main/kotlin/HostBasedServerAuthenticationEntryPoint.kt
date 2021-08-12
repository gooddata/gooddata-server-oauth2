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
package com.gooddata.oauth2.server.reactive

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.reactor.mono
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.server.DefaultServerRedirectStrategy
import org.springframework.security.web.server.ServerAuthenticationEntryPoint
import org.springframework.security.web.server.savedrequest.ServerRequestCache
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.net.URI

/**
 * [ServerAuthenticationEntryPoint] handles `XMLHttpRequest` are first redirected to `/appLogin` URI with
 * `401 Unauthorized` to allow JS apps to properly handle browser redirects. All other requests are redirected directly
 * to `/oauth2/authorization/{hostname}` using `302 Found` status code and `Location` header. It generates dynamic
 * redirects based on request's `Host` header as individual Auth2 providers are not defined statically during
 * Spring Context bootstrap.
 */
class HostBasedServerAuthenticationEntryPoint(
    private val requestCache: ServerRequestCache
) : ServerAuthenticationEntryPoint {

    private val redirectStrategy = DefaultServerRedirectStrategy()
    private val xmlHttpRequestServerRedirectStrategy = XMLHttpRequestServerRedirectStrategy()

    override fun commence(exchange: ServerWebExchange, e: AuthenticationException?): Mono<Void> =
        mono(Dispatchers.Unconfined) {
            if (exchange.isAjaxCall()) {
                val uri = URI.create(AppLoginWebFilter.APP_LOGIN_PATH)
                xmlHttpRequestServerRedirectStrategy.sendRedirect(exchange, uri)
            } else {
                val uri = URI.create("/oauth2/authorization/${exchange.request.uri.host}")
                requestCache
                    .saveRequest(exchange)
                    .then(redirectStrategy.sendRedirect(exchange, uri))
            }.awaitOrNull()
        }

    private fun ServerWebExchange.isAjaxCall() = this.request.headers["X-Requested-With"]?.first() == "XMLHttpRequest"
}
