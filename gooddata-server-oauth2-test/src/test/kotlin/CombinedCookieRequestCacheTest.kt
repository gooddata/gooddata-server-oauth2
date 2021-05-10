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
package com.gooddata.oauth2.server.test

import com.gooddata.oauth2.server.common.AuthenticationStoreClient
import com.gooddata.oauth2.server.common.CookieSecurityProperties
import com.gooddata.oauth2.server.common.CookieSerializer
import com.gooddata.oauth2.server.common.CookieServiceProperties
import com.gooddata.oauth2.server.common.Organization
import com.gooddata.oauth2.server.common.SPRING_REDIRECT_URI
import com.gooddata.oauth2.server.reactive.CookieServerRequestCache
import com.gooddata.oauth2.server.reactive.ReactiveCookieService
import com.gooddata.oauth2.server.servlet.CookieRequestCache
import com.gooddata.oauth2.server.servlet.CookieService
import com.google.crypto.tink.CleartextKeysetHandle
import com.google.crypto.tink.JsonKeysetReader
import io.mockk.coEvery
import io.mockk.mockk
import io.netty.handler.codec.http.cookie.CookieHeaderNames
import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.Test
import org.springframework.http.HttpCookie
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.mock.web.server.MockServerWebExchange
import strikt.api.expectThat
import strikt.assertions.isEqualTo
import strikt.assertions.isNotNull
import strikt.assertions.isTrue
import java.net.URI
import java.time.Duration
import java.time.Instant
import javax.servlet.http.Cookie

internal class CombinedCookieRequestCacheTest {
    @Language("JSON")
    private val keyset = """
        {
            "primaryKeyId": 482808123,
            "key": [
                {
                    "keyData": {
                        "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
                        "keyMaterialType": "SYMMETRIC",
                        "value": "GiBpR+IuA4xWtq5ZijTXae/Y9plMy0TMMc97wqdOrK7ndA=="
                    },
                    "outputPrefixType": "TINK",
                    "keyId": 482808123,
                    "status": "ENABLED"
                }
            ]
        }
    """

    private val client: AuthenticationStoreClient = mockk {
        coEvery { getOrganizationByHostname("localhost") } returns Organization("org")
        coEvery { getCookieSecurityProperties("org") } returns CookieSecurityProperties(
            keySet = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(keyset.toByteArray())),
            lastRotation = Instant.now(),
            rotationInterval = Duration.ofDays(1),
        )
    }

    private val properties = CookieServiceProperties(
        Duration.ofDays(1),
        CookieHeaderNames.SameSite.Lax,
        Duration.ofDays(1)
    )

    private val cookieSerializer = CookieSerializer(properties, client)

    private val reactiveCookieService = ReactiveCookieService(properties, cookieSerializer)

    private val cookieService = CookieService(properties, cookieSerializer)

    private val serverCache = CookieServerRequestCache(reactiveCookieService)

    private val cache = CookieRequestCache(cookieService)

    @Test
    fun `cookie saved by servlet can be read by reactive`() {
        val uri = "/requestURI?query=true"
        val servletRequest = MockHttpServletRequest("GET", uri).apply {
            serverName = "localhost"
            pathInfo = "/requestURI"
            queryString = "query=true"
        }
        val servletResponse = MockHttpServletResponse()

        cache.saveRequest(servletRequest, servletResponse)
        expectThat(servletResponse) {
            get {
                getCookie(SPRING_REDIRECT_URI)?.value?.let {
                    cookieSerializer.decodeCookie("localhost", it)
                }
            }.isEqualTo(uri)
        }

        val exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("http://localhost/requestURI")
                .cookie(HttpCookie(SPRING_REDIRECT_URI, servletResponse.getCookie(SPRING_REDIRECT_URI)?.value))
        )

        val redirectUri = serverCache.getRedirectUri(exchange)

        expectThat(redirectUri.blockOptional()) {
            get { isPresent }.isTrue()
            get { get() }.isEqualTo(URI.create(uri))
        }
    }

    @Test
    fun `cookie saved by reactive can be read by servlet`() {
        val uri = "/requestURI?query=true"
        val exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("http://localhost/requestURI").queryParam("query", "true")
        )

        val response = serverCache.saveRequest(exchange)

        expectThat(response.blockOptional()) {
            get { isEmpty }.isTrue()
        }
        expectThat(exchange.response) {
            get { cookies.getFirst(SPRING_REDIRECT_URI)?.value?.let { cookieSerializer.decodeCookie("localhost", it) } }
                .isEqualTo(uri)
        }

        val servletRequest = MockHttpServletRequest("GET", "/").apply {
            setCookies(Cookie(SPRING_REDIRECT_URI, exchange.response.cookies.getFirst(SPRING_REDIRECT_URI)?.value))
        }
        val servletResponse = MockHttpServletResponse()

        val savedRequest = cache.getRequest(servletRequest, servletResponse)

        expectThat(savedRequest).isNotNull().and {
            get { redirectUrl }.isEqualTo(uri)
        }
    }
}
