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

import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.databind.ObjectMapper
import mu.KotlinLogging
import org.springframework.http.ResponseCookie
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.time.Duration

/**
 * `ReactiveCookieService` is responsible for creation, storing and invalidation of HTTP cookies with respect
 * to configuration defined in [CookieServiceProperties].
 *
 * Cookies are Base64 encoded to avoid any problems with special characters.
 */
class ReactiveCookieService(
    private val properties: CookieServiceProperties,
    private val cookieSerializer: CookieSerializer,
) {

    private val logger = KotlinLogging.logger {}

    /**
     * Creates cookie with provided name and value and stores it to response of give exchange object.
     *
     * Param `value` is base64 encoded.
     */
    fun createCookie(exchange: ServerWebExchange, name: String, value: String) {
        val cookie = createResponseCookie(
            exchange.request,
            name,
            cookieSerializer.encodeCookie(exchange.request.uri.host, value),
            properties.duration
        )
        exchange.response.addCookie(cookie)
    }

    /**
     * Invalidates response cookie with given name - e.g. stores cookie with given name to response of given exchange
     * and sets its maxAge to 0.
     */
    fun invalidateCookie(exchange: ServerWebExchange, name: String) {
        logger.debug { "Invalidate cookie name=$name" }
        val cookie = createResponseCookie(exchange.request, name, null, Duration.ZERO)
        exchange.response.addCookie(cookie)
    }

    private fun createResponseCookie(
        request: ServerHttpRequest,
        name: String,
        value: String?,
        age: Duration
    ): ResponseCookie {
        return ResponseCookie.from(name, value ?: "")
            .path(request.path.contextPath().value() + "/")
            .maxAge(age)
            .httpOnly(true)
            .secure(request.isHttps())
            .sameSite(properties.sameSite.name)
            .build()
    }

    private fun ServerHttpRequest.isHttps() = "https".equals(uri.scheme, ignoreCase = true)

    /**
     * This method takes request from this exchange, loads first cookie of given name and performs base64 decode.
     */
    internal fun decodeCookie(
        request: ServerHttpRequest,
        name: String
    ): Mono<String> {
        return Mono.justOrEmpty(request.cookies.getFirst(name))
            .map { cookie -> cookieSerializer.decodeCookie(request.uri.host, cookie.value) }
            .onErrorResume(IllegalArgumentException::class.java) { exception ->
                logger.warn(exception) { "Cookie cannot be decoded" }
                Mono.empty()
            }
    }

    /**
     * This method takes request from this exchange, loads first cookie of given name and performs base64 decode.
     * Finally it uses provided [ObjectMapper] to parse stored JSON.
     */
    internal inline fun <reified T> decodeCookie(
        request: ServerHttpRequest,
        name: String,
        mapper: ObjectMapper,
    ): Mono<T> = decodeCookie(request, name, mapper, T::class.java)

    /**
     * This method takes request from this exchange, loads first cookie of given name and performs base64 decode.
     * Finally it uses provided [ObjectMapper] to parse stored JSON.
     */
    private fun <T> decodeCookie(
        request: ServerHttpRequest,
        name: String,
        mapper: ObjectMapper,
        valueType: Class<T>,
    ): Mono<T> {
        return decodeCookie(request, name)
            .map { cookieValue -> mapper.readValue(cookieValue, valueType) }
            .onErrorResume(JsonProcessingException::class.java) { exception ->
                logger.warn(exception) { "Cookie cannot be parsed" }
                Mono.empty()
            }
    }
}
