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

import com.gooddata.oauth2.server.common.CookieSerializer
import com.gooddata.oauth2.server.common.CookieServiceProperties
import com.gooddata.oauth2.server.common.jackson.mapper
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import io.netty.handler.codec.http.cookie.CookieHeaderNames
import net.javacrumbs.jsonunit.core.util.ResourceUtils.resource
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.http.HttpCookie
import org.springframework.http.ResponseCookie
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.util.CollectionUtils
import org.springframework.web.server.ServerWebExchange
import strikt.api.expectThat
import strikt.assertions.isEqualTo
import strikt.assertions.isFalse
import strikt.assertions.isTrue
import java.time.Duration
import java.util.Optional

internal class ReactiveCookieServiceTest {

    private val name = "name"
    private val duration = Duration.ofHours(1)
    private val value = "value"

    private val exchange: ServerWebExchange = mockk()

    private val properties = CookieServiceProperties(duration, CookieHeaderNames.SameSite.Lax, "")

    private val cookieSerializer = CookieSerializer(properties)

    private val cookieService = ReactiveCookieService(properties, cookieSerializer)

    private val encodedValue = cookieSerializer.encodeCookie(value)

    @BeforeEach
    internal fun setUp() {
        every { exchange.request.path.contextPath().value() } returns ""
        every { exchange.request.uri.scheme } returns "http"
    }

    @Test
    fun `creates cookie`() {
        val slot = slot<ResponseCookie>()
        every { exchange.response.addCookie(capture(slot)) } returns Unit

        cookieService.createCookie(exchange, name, value)

        val cookie = slot.captured

        verify(exactly = 1) { exchange.response.addCookie(any()) }

        expectThat(cookie) {
            get(ResponseCookie::getName).isEqualTo(name)
            get(ResponseCookie::getValue).isEqualTo(encodedValue)
            get(ResponseCookie::getValue).assert("is properly encoded") {
                cookieSerializer.decodeCookie(it).contentEquals(value)
            }
            get(ResponseCookie::getPath).isEqualTo("/")
            get(ResponseCookie::isHttpOnly).isTrue()
            get(ResponseCookie::isSecure).isFalse()
            get(ResponseCookie::getSameSite).isEqualTo("Lax")
            get(ResponseCookie::getMaxAge).isEqualTo(duration)
        }
    }

    @Test
    fun `invalidates cookie`() {
        val slot = slot<ResponseCookie>()
        every { exchange.response.addCookie(capture(slot)) } returns Unit

        cookieService.invalidateCookie(exchange, name)

        val cookie = slot.captured

        verify(exactly = 1) { exchange.response.addCookie(any()) }
        expectThat(cookie) {
            get(ResponseCookie::getName).isEqualTo(name)
            get(ResponseCookie::getValue).isEqualTo("")
            get(ResponseCookie::getPath).isEqualTo("/")
            get(ResponseCookie::isHttpOnly).isTrue()
            get(ResponseCookie::isSecure).isFalse()
            get(ResponseCookie::getSameSite).isEqualTo("Lax")
            get(ResponseCookie::getMaxAge).isEqualTo(Duration.ZERO)
        }
    }

    @Test
    fun `decodes cookie from empty exchange`() {
        every { exchange.request.cookies } returns CollectionUtils.toMultiValueMap(emptyMap())

        val value = cookieService.decodeCookie(exchange.request, name)

        expectThat(value.blockOptional()) {
            get(Optional<String>::isEmpty).isTrue()
        }
    }

    @Test
    fun `decodes cookie from invalid exchange`() {
        every { exchange.request.cookies } returns CollectionUtils.toMultiValueMap(
            mapOf(name to listOf(HttpCookie(name, "something")))
        )

        val value = cookieService.decodeCookie(exchange.request, name)

        expectThat(value.blockOptional()) {
            get(Optional<String>::isEmpty).isTrue()
        }
    }

    @Test
    fun `decodes cookie from exchange`() {
        every { exchange.request.cookies } returns CollectionUtils.toMultiValueMap(
            mapOf(name to listOf(HttpCookie(name, encodedValue)))
        )

        val value = cookieService.decodeCookie(exchange.request, name)

        expectThat(value.blockOptional()) {
            get(Optional<String>::isPresent).isTrue()
            get(Optional<String>::get).isEqualTo("value")
        }
    }

    @Test
    fun `decodes and cannot parse cookie from exchange`() {
        every { exchange.request.cookies } returns CollectionUtils.toMultiValueMap(
            mapOf(name to listOf(HttpCookie(name, encodedValue)))
        )

        val value = cookieService.decodeCookie(
            exchange.request, name, mapper, OAuth2AuthorizationRequest::class.java
        )

        expectThat(value.blockOptional()) {
            get(Optional<OAuth2AuthorizationRequest>::isEmpty).isTrue()
        }
    }

    @Test
    fun `decodes and parses cookie from exchange`() {
        val body = resource("mock_authorization_request.json").readText()
        every { exchange.request.cookies } returns CollectionUtils.toMultiValueMap(
            mapOf(name to listOf(HttpCookie(name, cookieSerializer.encodeCookie(body))))
        )

        val value = cookieService.decodeCookie(
            exchange.request, name, mapper, OAuth2AuthorizationRequest::class.java
        )

        expectThat(value.blockOptional()) {
            get(Optional<OAuth2AuthorizationRequest>::isPresent).isTrue()
            get(Optional<OAuth2AuthorizationRequest>::get)
                .get(OAuth2AuthorizationRequest::getAuthorizationUri)
                .isEqualTo("authorizationUri")
        }
    }
}
