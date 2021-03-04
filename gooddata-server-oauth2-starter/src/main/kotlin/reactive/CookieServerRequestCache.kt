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
package com.gooddata.oauth2.server.reactive

import org.apache.commons.logging.Log
import org.apache.commons.logging.LogFactory
import reactor.core.publisher.Mono
import org.springframework.core.log.LogMessage
import org.springframework.http.HttpCookie
import org.springframework.http.HttpMethod
import org.springframework.http.MediaType
import org.springframework.http.ResponseCookie
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.http.server.reactive.ServerHttpResponse
import org.springframework.security.web.server.savedrequest.ServerRequestCache
import org.springframework.security.web.server.util.matcher.AndServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.MediaTypeServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.NegatedServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers
import org.springframework.util.Assert
import org.springframework.util.MultiValueMap
import org.springframework.web.server.ServerWebExchange
import java.net.URI
import java.time.Duration
import java.util.Base64

/**
 * An implementation of [ServerRequestCache] that saves the requested URI in a
 * cookie.
 *
 * @author Eleftheria Stein
 * @author Mathieu Ouellet
 * @since 5.4
 */
class CookieServerRequestCache : ServerRequestCache {
    private var saveRequestMatcher: ServerWebExchangeMatcher = createDefaultRequestMatcher()

    /**
     * Sets the matcher to determine if the request should be saved. The default is to
     * match on any GET request.
     * @param saveRequestMatcher the [ServerWebExchangeMatcher] that determines if
     * the request should be saved
     */
    fun setSaveRequestMatcher(saveRequestMatcher: ServerWebExchangeMatcher) {
        Assert.notNull(saveRequestMatcher, "saveRequestMatcher cannot be null")
        this.saveRequestMatcher = saveRequestMatcher
    }

    override fun saveRequest(exchange: ServerWebExchange): Mono<Void> {
        return saveRequestMatcher.matches(exchange).filter { m -> m.isMatch() }.map { exchange.getResponse() }
            .map(ServerHttpResponse::getCookies).doOnNext { cookies ->
                val redirectUriCookie: ResponseCookie =
                    createRedirectUriCookie(
                        exchange.getRequest()
                    )
                cookies.add(
                    REDIRECT_URI_COOKIE_NAME,
                    redirectUriCookie
                )
                logger.debug(
                    LogMessage.format(
                        "Request added to Cookie: %s",
                        redirectUriCookie
                    )
                )
            }.then()
    }

    override fun getRedirectUri(exchange: ServerWebExchange): Mono<URI> {
        val cookieMap: MultiValueMap<String, HttpCookie> = exchange.getRequest().getCookies()
        return Mono.justOrEmpty(cookieMap.getFirst(REDIRECT_URI_COOKIE_NAME)).map(HttpCookie::getValue)
            .map { encodedCookieValue: String ->
                decodeCookie(
                    encodedCookieValue
                )
            }
            .onErrorResume(IllegalArgumentException::class.java) { Mono.empty() }.map { str: String? ->
                URI.create(
                    str
                )
            }
    }

    override fun removeMatchingRequest(exchange: ServerWebExchange): Mono<ServerHttpRequest> {
        return Mono.just(exchange.getResponse()).map(ServerHttpResponse::getCookies).doOnNext { cookies ->
            cookies.add(
                REDIRECT_URI_COOKIE_NAME,
                invalidateRedirectUriCookie(
                    exchange.getRequest()
                )
            )
        }
            .thenReturn(exchange.getRequest())
    }

    companion object {
        private const val REDIRECT_URI_COOKIE_NAME = "REDIRECT_URI"
        private val COOKIE_MAX_AGE = Duration.ofSeconds(-1)
        private val logger: Log = LogFactory.getLog(CookieServerRequestCache::class.java)
        private fun createRedirectUriCookie(request: ServerHttpRequest): ResponseCookie {
            val path: String = request.getPath().pathWithinApplication().value()
            val query: String = request.getURI().getRawQuery()
            val redirectUri = "$path?$query"
            return createResponseCookie(request, encodeCookie(redirectUri), COOKIE_MAX_AGE)
        }

        private fun invalidateRedirectUriCookie(request: ServerHttpRequest): ResponseCookie {
            return createResponseCookie(request, null, Duration.ZERO)
        }

        private fun createResponseCookie(
            request: ServerHttpRequest,
            cookieValue: String?,
            age: Duration
        ): ResponseCookie {
            return ResponseCookie.from(REDIRECT_URI_COOKIE_NAME, cookieValue ?: "")
                .path(request.getPath().contextPath().value().toString() + "/").maxAge(age).httpOnly(true)
                .secure("https".equals(request.getURI().getScheme(), ignoreCase = true)).sameSite("Lax").build()
        }

        private fun encodeCookie(cookieValue: String): String {
            return String(Base64.getEncoder().encode(cookieValue.toByteArray()))
        }

        private fun decodeCookie(encodedCookieValue: String): String {
            return String(Base64.getDecoder().decode(encodedCookieValue.toByteArray()))
        }

        private fun createDefaultRequestMatcher(): ServerWebExchangeMatcher {
            val get: ServerWebExchangeMatcher = ServerWebExchangeMatchers.pathMatchers(HttpMethod.GET, "/**")
            val notFavicon: ServerWebExchangeMatcher = NegatedServerWebExchangeMatcher(
                ServerWebExchangeMatchers.pathMatchers("/favicon.*")
            )
            val html = MediaTypeServerWebExchangeMatcher(MediaType.TEXT_HTML)
            html.setIgnoredMediaTypes(setOf(MediaType.ALL))
            return AndServerWebExchangeMatcher(get, notFavicon, html)
        }
    }
}
