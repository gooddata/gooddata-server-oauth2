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

    private val request: HttpServletRequest = mockk {
        every { contextPath } returns ""
        every { scheme } returns "http"
        every { serverName } returns HOSTNAME
    }

    private val response: HttpServletResponse = mockk(relaxed = true)

    private val client: AuthenticationStoreClient = mockk {
        coEvery { getOrganizationByHostname(HOSTNAME) } returns Organization(ORG_ID)
        coEvery { getCookieSecurityProperties(ORG_ID) } returns COOKIE_SECURITY_PROPS
    }

    private val cookieSerializer = CookieSerializer(SERVICE_PROPERTIES, client)

    private val cookieService = CookieService(SERVICE_PROPERTIES, cookieSerializer)

    @Test
    fun `creates cookie`() {
        cookieService.createCookie(request, response, COOKIE_NAME, COOKIE_VALUE)

        val slot = slot<Cookie>()
        verify(exactly = 1) { response.addCookie(capture(slot)) }
        expectThat(slot.captured) {
            get(Cookie::getName).isEqualTo(COOKIE_NAME)
            get(Cookie::getValue).describedAs("is properly encoded")
                .get { cookieSerializer.decodeCookie(HOSTNAME, this) }.isEqualTo(COOKIE_VALUE)
            get(Cookie::getPath).isEqualTo("/")
            get(Cookie::isHttpOnly).isTrue()
            get(Cookie::getMaxAge).isEqualTo(Duration.ofDays(1).seconds.toInt())
        }
    }

    @Test
    fun `invalidates cookie`() {
        cookieService.invalidateCookie(request, response, COOKIE_NAME)

        val slot = slot<Cookie>()
        verify(exactly = 1) { response.addCookie(capture(slot)) }
        expectThat(slot.captured) {
            get(Cookie::getName).isEqualTo(COOKIE_NAME)
            get(Cookie::getValue).isEqualTo("")
            get(Cookie::getPath).isEqualTo("/")
            get(Cookie::isHttpOnly).isTrue()
            get(Cookie::getMaxAge).isEqualTo(Duration.ZERO.seconds.toInt())
        }
    }

    @Test
    fun `decodes cookie from empty exchange`() {
        every { request.cookies } returns emptyArray()

        val value = cookieService.decodeCookie(request, COOKIE_NAME)

        expectThat(value).isNull()
    }

    @Test
    fun `decodes cookie from invalid exchange`() {
        every { request.cookies } returns arrayOf(Cookie(COOKIE_NAME, "something"))

        val value = cookieService.decodeCookie(request, COOKIE_NAME)

        expectThat(value).isNull()
    }

    @Test
    fun `decodes cookie from exchange`() {
        val encodedValue = cookieSerializer.encodeCookie(HOSTNAME, COOKIE_VALUE)
        every { request.cookies } returns arrayOf(Cookie(COOKIE_NAME, encodedValue))

        val value = cookieService.decodeCookie(request, COOKIE_NAME)

        expectThat(value).isEqualTo("value")
    }

    @Test
    fun `decodes and cannot parse cookie from exchange`() {
        val encodedValue = cookieSerializer.encodeCookie(HOSTNAME, COOKIE_VALUE)
        every { request.cookies } returns arrayOf(Cookie(COOKIE_NAME, encodedValue))

        val value = cookieService.decodeCookie(
            request, COOKIE_NAME, mapper, OAuth2AuthorizationRequest::class.java
        )

        expectThat(value).isNull()
    }

    @Test
    fun `decodes and parses cookie from request`() {
        val body = resource("mock_authorization_request.json").readText()
        every { request.cookies } returns arrayOf(Cookie(COOKIE_NAME, cookieSerializer.encodeCookie(HOSTNAME, body)))

        val value = cookieService.decodeCookie(request, COOKIE_NAME, mapper, OAuth2AuthorizationRequest::class.java)

        expectThat(value).isNotNull()
            .get(OAuth2AuthorizationRequest::getAuthorizationUri).isEqualTo("authorizationUri")
    }

    companion object {
        private const val HOSTNAME = "localhost"
        private const val ORG_ID = "org"
        private const val COOKIE_NAME = "name"
        private const val COOKIE_VALUE = "value"

        private val SERVICE_PROPERTIES = CookieServiceProperties(
            Duration.ofDays(1),
            CookieHeaderNames.SameSite.Lax,
            Duration.ofDays(1)
        )

        @Language("JSON")
        private val COOKIE_KEYSET = """
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

        private val COOKIE_SECURITY_PROPS = CookieSecurityProperties(
            keySet = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(COOKIE_KEYSET.toByteArray())),
            lastRotation = Instant.now(),
            rotationInterval = Duration.ofDays(1),
        )
    }
}
