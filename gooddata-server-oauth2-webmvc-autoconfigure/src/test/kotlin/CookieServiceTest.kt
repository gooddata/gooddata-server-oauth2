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
import com.gooddata.oauth2.server.common.jackson.mapper
import com.google.crypto.tink.CleartextKeysetHandle
import com.google.crypto.tink.JsonKeysetReader
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import io.netty.handler.codec.http.cookie.CookieHeaderNames
import net.javacrumbs.jsonunit.core.util.ResourceUtils.resource
import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import strikt.api.expectThat
import strikt.assertions.isEqualTo
import strikt.assertions.isNotNull
import strikt.assertions.isNull
import strikt.assertions.isTrue
import java.time.Duration
import java.time.Instant
import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

internal class CookieServiceTest {

    private val name = "name"
    private val duration = Duration.ofHours(1)
    private val value = "value"

    private val request: HttpServletRequest = mockk()

    private val response: HttpServletResponse = mockk()

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

    private val cookieService = CookieService(properties, cookieSerializer)

    private val encodedValue = cookieSerializer.encodeCookie("localhost", value)

    @BeforeEach
    internal fun setUp() {
        every { request.contextPath } returns ""
        every { request.scheme } returns "http"
    }

    @Test
    fun `creates cookie`() {
        val slot = slot<Cookie>()
        every { response.addCookie(capture(slot)) } returns Unit
        every { request.serverName } returns "localhost"

        cookieService.createCookie(request, response, name, value)

        val cookie = slot.captured

        verify(exactly = 1) { response.addCookie(any()) }
        expectThat(cookie) {
            get(Cookie::getName).isEqualTo(name)
            get(Cookie::getValue).assert("is properly encoded") {
                cookieSerializer.decodeCookie("localhost", it).contentEquals(value)
            }
            get(Cookie::getPath).isEqualTo("/")
            get(Cookie::isHttpOnly).isTrue()
            get(Cookie::getMaxAge).isEqualTo(duration.seconds.toInt())
        }
    }

    @Test
    fun `invalidates cookie`() {
        val slot = slot<Cookie>()
        every { response.addCookie(capture(slot)) } returns Unit

        cookieService.invalidateCookie(request, response, name)

        val cookie = slot.captured

        verify(exactly = 1) { response.addCookie(any()) }
        expectThat(cookie) {
            get(Cookie::getName).isEqualTo(name)
            get(Cookie::getValue).isEqualTo("")
            get(Cookie::getPath).isEqualTo("/")
            get(Cookie::isHttpOnly).isTrue()
            get(Cookie::getMaxAge).isEqualTo(Duration.ZERO.seconds.toInt())
        }
    }

    @Test
    fun `decodes cookie from empty exchange`() {
        every { request.cookies } returns emptyArray()

        val value = cookieService.decodeCookie(request, name)

        expectThat(value).isNull()
    }

    @Test
    fun `decodes cookie from invalid exchange`() {
        every { request.cookies } returns arrayOf(Cookie(name, "something"))
        every { request.serverName } returns "localhost"

        val value = cookieService.decodeCookie(request, name)

        expectThat(value).isNull()
    }

    @Test
    fun `decodes cookie from exchange`() {
        every { request.cookies } returns arrayOf(Cookie(name, encodedValue))
        every { request.serverName } returns "localhost"

        val value = cookieService.decodeCookie(request, name)

        expectThat(value).isEqualTo("value")
    }

    @Test
    fun `decodes and cannot parse cookie from exchange`() {
        every { request.cookies } returns arrayOf(Cookie(name, encodedValue))
        every { request.serverName } returns "localhost"

        val value = cookieService.decodeCookie(
            request, name, mapper, OAuth2AuthorizationRequest::class.java
        )

        expectThat(value).isNull()
    }

    @Test
    fun `decodes and parses cookie from request`() {
        val body = resource("mock_authorization_request.json").readText()
        every { request.cookies } returns arrayOf(Cookie(name, cookieSerializer.encodeCookie("localhost", body)))
        every { request.serverName } returns "localhost"

        val value = cookieService.decodeCookie(
            request, name, mapper, OAuth2AuthorizationRequest::class.java
        )

        expectThat(value) {
            isNotNull()
                .get(OAuth2AuthorizationRequest::getAuthorizationUri)
                .isEqualTo("authorizationUri")
        }
    }
}
