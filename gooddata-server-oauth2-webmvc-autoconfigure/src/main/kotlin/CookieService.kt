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

import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.databind.ObjectMapper
import com.gooddata.oauth2.server.common.CookieSerializer
import com.gooddata.oauth2.server.common.CookieServiceProperties
import mu.KotlinLogging
import org.springframework.web.util.WebUtils
import java.time.Duration
import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

private val logger = KotlinLogging.logger {}

/**
 * `CookieService` is responsible for creation, storing and invalidation of HTTP cookies with respect
 * to configuration defined in [CookieServiceProperties].
 *
 * Cookies are base64 encoded to avoid any problems with special characters.
 */
class CookieService(
    private val properties: CookieServiceProperties,
    private val cookieSerializer: CookieSerializer,
) {

    /**
     * Creates cookie with provided name and value and stores it to response.
     *
     * Param `value` is base64 encoded.
     */
    fun createCookie(request: HttpServletRequest, response: HttpServletResponse, name: String, value: String) {
        val cookie = createResponseCookie(
            request,
            name,
            cookieSerializer.encodeCookie(value),
            properties.duration
        )
        response.addCookie(cookie)
    }

    /**
     * Invalidates response cookie with given name - e.g. stores cookie with given name to response
     * and sets its maxAge to 0.
     */
    fun invalidateCookie(request: HttpServletRequest, response: HttpServletResponse, name: String) {
        val cookie = createResponseCookie(request, name, null, Duration.ZERO)
        response.addCookie(cookie)
    }

    private fun createResponseCookie(
        request: HttpServletRequest,
        name: String,
        value: String?,
        age: Duration
    ): Cookie {
        return Cookie(name, value ?: "").apply {
            path = request.contextPath + "/"
            maxAge = age.seconds.toInt()
            isHttpOnly = true
            secure = "https".equals(request.scheme, ignoreCase = true)
        }
    }

    /**
     * This method takes request from this request, loads first cookie of given name and performs base64 decode.
     */
    internal fun decodeCookie(request: HttpServletRequest, name: String): String? = try {
        WebUtils.getCookie(request, name)?.value?.let { cookieSerializer.decodeCookie(it) }
    } catch (e: IllegalArgumentException) {
        logger.warn(e) { "Cookie cannot be decoded" }
        null
    }

    /**
     * This method takes request from this request, loads first cookie of given name and performs base64 decode. Finally
     * it uses provided [ObjectMapper] to parse stored JSON.
     */
    internal fun <T> decodeCookie(
        request: HttpServletRequest,
        name: String,
        mapper: ObjectMapper,
        valueType: Class<T>
    ): T? = try {
        decodeCookie(request, name)?.let {
            mapper.readValue(it, valueType)
        }
    } catch (e: JsonProcessingException) {
        logger.warn(e) { "Cookie cannot be parsed" }
        null
    }
}
