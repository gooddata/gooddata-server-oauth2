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

import com.gooddata.oauth2.server.common.AuthenticationStoreClient
import com.gooddata.oauth2.server.common.CookieSecurityProperties
import com.gooddata.oauth2.server.common.CookieSerializer
import com.gooddata.oauth2.server.common.CookieServiceProperties
import com.gooddata.oauth2.server.common.Organization
import com.gooddata.oauth2.server.common.SPRING_REDIRECT_URI
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
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import strikt.api.expectThat
import strikt.assertions.isEqualTo
import strikt.assertions.isNotNull
import strikt.assertions.isNull
import java.time.Duration
import java.time.Instant
import javax.servlet.http.Cookie

internal class CookieRequestCacheTest {

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
        coEvery { getOrganizationByHostname("localhost") } returns Organization("org")
        coEvery { getCookieSecurityProperties("org") } returns CookieSecurityProperties(
            keySet = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(keyset.toByteArray())),
            lastRotation = Instant.now(),
            rotationInterval = Duration.ofDays(1),
        )
    }

    private val cookieSerializer = CookieSerializer(properties, client)

    private val cookieService = spyk(CookieService(properties, cookieSerializer))

    private val cache = CookieRequestCache(cookieService)

    @Test
    fun `should save redirect URI`() {
        val slot = slot<String>()
        every { cookieService.createCookie(any(), any(), any(), capture(slot)) } returns Unit

        val request = MockHttpServletRequest("GET", "/requestURI?query=true").apply {
            pathInfo = "/requestURI"
            queryString = "query=true"
        }
        val response = MockHttpServletResponse()

        cache.saveRequest(request, response)

        verify(exactly = 1) { cookieService.createCookie(request, response, SPRING_REDIRECT_URI, any()) }

        expectThat(slot.captured).isEqualTo("/requestURI?query=true")
    }

    @Test
    fun `should remove redirect URI from cookies`() {
        every { cookieService.invalidateCookie(any(), any(), any()) } returns Unit

        val request = MockHttpServletRequest("GET", "/requestURI?query=true")
        val response = MockHttpServletResponse()

        cache.removeRequest(request, response)

        verify(exactly = 1) { cookieService.invalidateCookie(request, response, SPRING_REDIRECT_URI) }
    }

    @Test
    fun `should not load redirect URI when nothing is stored in cookies`() {
        val request = MockHttpServletRequest("GET", "/requestURI?query=true")
        val response = MockHttpServletResponse()

        val savedRequest = cache.getRequest(request, response)

        expectThat(savedRequest).isNull()
    }

    @Test
    fun `should not load redirect URI when nonsense is stored in cookies`() {
        val request = MockHttpServletRequest("GET", "/requestURI?query=true").apply {
            setCookies(Cookie(SPRING_REDIRECT_URI, "something"))
        }
        val response = MockHttpServletResponse()

        val savedRequest = cache.getRequest(request, response)

        expectThat(savedRequest).isNull()
    }

    @Test
    fun `should load redirect URI from cookie`() {
        val redirect = "/requestURI?query=true"
        val request = MockHttpServletRequest("GET", "/requestURI?query=true").apply {
            setCookies(Cookie(SPRING_REDIRECT_URI, cookieSerializer.encodeCookie("localhost", redirect)))
        }
        val response = MockHttpServletResponse()

        val savedRequest = cache.getRequest(request, response)

        expectThat(savedRequest).isNotNull().and {
            get { redirectUrl }.isEqualTo(redirect)
        }
    }

    @Test
    fun `should get matching request when redirect URI matches`() {
        val redirect = "/requestURI?query=true"
        every { cookieService.invalidateCookie(any(), any(), any()) } returns Unit
        val request = MockHttpServletRequest("GET", "/requestURI?query=true").apply {
            pathInfo = "/requestURI"
            queryString = "query=true"
            setCookies(Cookie(SPRING_REDIRECT_URI, cookieSerializer.encodeCookie("localhost", redirect)))
        }
        val response = MockHttpServletResponse()

        val matchingRequest = cache.getMatchingRequest(request, response)

        expectThat(matchingRequest).isEqualTo(request)

        verify(exactly = 1) {
            cookieService.invalidateCookie(request, response, SPRING_REDIRECT_URI)
        }
    }

    @Test
    fun `should not get matching request when redirect URI matches`() {
        every { cookieService.invalidateCookie(any(), any(), any()) } returns Unit
        val request = MockHttpServletRequest("GET", "/requestURI?query=true").apply {
            pathInfo = "/requestURI"
            queryString = "query=true"
            setCookies(Cookie(SPRING_REDIRECT_URI, cookieSerializer.encodeCookie("localhost", "/other")))
        }
        val response = MockHttpServletResponse()

        val matchingRequest = cache.getMatchingRequest(request, response)

        expectThat(matchingRequest).isNull()

        verify(exactly = 0) {
            cookieService.invalidateCookie(any(), any(), any())
        }
    }
}
