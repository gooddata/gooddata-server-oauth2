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

import com.google.crypto.tink.CleartextKeysetHandle
import com.google.crypto.tink.JsonKeysetReader
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.spyk
import io.mockk.verify
import io.netty.handler.codec.http.cookie.CookieHeaderNames
import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.Test
import org.springframework.http.HttpCookie
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.util.CollectionUtils
import org.springframework.web.server.ServerWebExchange
import strikt.api.expectThat
import strikt.assertions.isEqualTo
import strikt.assertions.isTrue
import java.net.URI
import java.time.Duration
import java.time.Instant

internal class CookieServerRequestCacheTest {

    private val properties = CookieServiceProperties(
        Duration.ofDays(1),
        CookieHeaderNames.SameSite.Lax,
        Duration.ofDays(1)
    )

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
        coEvery { getCookieSecurityProperties(ORG_ID) } returns CookieSecurityProperties(
            keySet = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(keyset.toByteArray())),
            lastRotation = Instant.now(),
            rotationInterval = Duration.ofDays(1),
        )
    }

    private val cookieSerializer = CookieSerializer(properties, client)

    private val cookieService = spyk(ReactiveCookieService(properties, cookieSerializer))

    private val cache = CookieServerRequestCache(cookieService)

    @Test
    fun `should save redirect URI`() {
        val slot = slot<String>()
        val exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("http://localhost/requestURI").queryParam("query", "true")
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
        val request = MockServerHttpRequest.get("http://localhost/requestURI").queryParam("query", "true").build()
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
            MockServerHttpRequest.get("http://localhost/requestURI").queryParam("query", "true")
        )

        val uri = cache.getRedirectUri(exchange)

        expectThat(uri.blockOptional()) {
            get { isEmpty }.isTrue()
        }
    }

    @Test
    fun `should not load redirect URI when nonsense is stored in cookies`() {
        val exchange = mockk<ServerWebExchange> {
            every { request.uri.host } returns "localhost"
            every { attributes[OrganizationWebFilter.ORGANIZATION_CACHE_KEY] } returns Organization(ORG_ID)
            every { request.cookies } returns CollectionUtils.toMultiValueMap(
                mapOf(SPRING_REDIRECT_URI to listOf(HttpCookie(SPRING_REDIRECT_URI, "something")))
            )
        }

        val uri = cache.getRedirectUri(exchange)

        expectThat(uri.blockOptional()) {
            get { isEmpty }.isTrue()
        }
    }

    @Test
    fun `should load redirect URI from cookie`() {
        val webExchange = mockk<ServerWebExchange> {
            every { request.uri.host } returns "localhost"
            every { attributes[OrganizationWebFilter.ORGANIZATION_CACHE_KEY] } returns Organization(ORG_ID)
        }

        val redirect = "/requestURI?query=true"
        val exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("http://localhost/").cookie(
                HttpCookie(SPRING_REDIRECT_URI, cookieSerializer.encodeCookie(webExchange, redirect))
            )
        )

        val uri = cache.getRedirectUri(exchange)

        expectThat(uri.blockOptional()) {
            get { isPresent }.isTrue()
            get { get() }.isEqualTo(URI.create(redirect))
        }
    }

    companion object {
        const val ORG_ID = "org"
    }
}
