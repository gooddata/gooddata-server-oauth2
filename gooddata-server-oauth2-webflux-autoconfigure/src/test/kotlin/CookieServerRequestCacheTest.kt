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
import com.gooddata.oauth2.server.common.SPRING_REDIRECT_URI
import io.mockk.every
import io.mockk.slot
import io.mockk.spyk
import io.mockk.verify
import io.netty.handler.codec.http.cookie.CookieHeaderNames
import org.junit.jupiter.api.Test
import org.springframework.http.HttpCookie
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import strikt.api.expectThat
import strikt.assertions.isEqualTo
import strikt.assertions.isTrue
import java.net.URI
import java.time.Duration

internal class CookieServerRequestCacheTest {

    private val properties = CookieServiceProperties(Duration.ofDays(1), CookieHeaderNames.SameSite.Lax, "")

    private val cookieSerializer = CookieSerializer(properties)

    private val cookieService = spyk(ReactiveCookieService(properties, cookieSerializer))

    private val cache = CookieServerRequestCache(cookieService)

    @Test
    fun `should save redirect URI`() {
        val slot = slot<String>()
        val exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/requestURI").queryParam("query", "true")
        )
        every { cookieService.createCookie(any(), any(), capture(slot)) } returns Unit

        val response = cache.saveRequest(exchange)

        expectThat(response.blockOptional()) {
            get { isEmpty }.isTrue()
        }

        verify(exactly = 1) { cookieService.createCookie(exchange, SPRING_REDIRECT_URI, any()) }
    }

    @Test
    fun `should remove redirect URI from cookies`() {
        val request = MockServerHttpRequest.get("/requestURI").queryParam("query", "true").build()
        val exchange = MockServerWebExchange.from(request)
        every { cookieService.invalidateCookie(any(), any()) } returns Unit

        val matchingRequest = cache.removeMatchingRequest(exchange)

        expectThat(matchingRequest.blockOptional()) {
            get { isPresent }.isTrue()
            get { get() }.isEqualTo(request)
        }

        verify(exactly = 1) { cookieService.invalidateCookie(exchange, SPRING_REDIRECT_URI) }
    }

    @Test
    fun `should not load redirect URI when nothing is stored in cookies`() {
        val exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/requestURI").queryParam("query", "true")
        )

        val uri = cache.getRedirectUri(exchange)

        expectThat(uri.blockOptional()) {
            get { isEmpty }.isTrue()
        }
    }

    @Test
    fun `should not load redirect URI when nonsense is stored in cookies`() {
        val exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/").cookie(HttpCookie(SPRING_REDIRECT_URI, "something"))
        )

        val uri = cache.getRedirectUri(exchange)

        expectThat(uri.blockOptional()) {
            get { isEmpty }.isTrue()
        }
    }

    @Test
    fun `should load redirect URI from cookie`() {
        val redirect = "/requestURI?query=true"
        val exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/").cookie(
                HttpCookie(SPRING_REDIRECT_URI, cookieSerializer.encodeCookie(redirect))
            )
        )

        val uri = cache.getRedirectUri(exchange)

        expectThat(uri.blockOptional()) {
            get { isPresent }.isTrue()
            get { get() }.isEqualTo(URI.create(redirect))
        }
    }
}
