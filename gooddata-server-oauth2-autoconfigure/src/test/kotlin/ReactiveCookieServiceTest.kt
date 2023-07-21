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

import com.gooddata.oauth2.server.jackson.mapper
import com.google.crypto.tink.CleartextKeysetHandle
import com.google.crypto.tink.JsonKeysetReader
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.verify
import io.netty.handler.codec.http.cookie.CookieHeaderNames
import net.javacrumbs.jsonunit.core.util.ResourceUtils.resource
import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.springframework.http.HttpCookie
import org.springframework.http.ResponseCookie
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.util.CollectionUtils
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import strikt.api.expectThat
import strikt.assertions.isEqualTo
import strikt.assertions.isFalse
import strikt.assertions.isTrue
import java.net.URI
import java.time.Duration
import java.time.Instant
import java.util.Optional

internal class ReactiveCookieServiceTest {

    private val exchange: ServerWebExchange = mockk(relaxed = true) {
        every { request.path.contextPath().value() } returns ""
        every { request.uri } returns URI.create("http://$HOSTNAME")
    }

    private val client: AuthenticationStoreClient = mockk {
        coEvery { getCookieSecurityProperties(ORG_ID) } returns COOKIE_SECURITY_PROPS
    }

    private val cookieSerializer = CookieSerializer(SERVICE_PROPERTIES, client)

    private val cookieService = ReactiveCookieService(SERVICE_PROPERTIES, cookieSerializer)

    @Test
    fun `creates cookie`() {
        cookieService.createCookie(exchange, COOKIE_NAME, COOKIE_VALUE)

        val slot = slot<ResponseCookie>()
        verify(exactly = 1) { exchange.response.addCookie(capture(slot)) }

        expectThat(slot.captured) {
            get(ResponseCookie::getName).isEqualTo(COOKIE_NAME)
            get(ResponseCookie::getValue).describedAs("is properly encoded")
                .get { cookieSerializer.decodeCookie(HOSTNAME, this) }.isEqualTo(COOKIE_VALUE)
            get(ResponseCookie::getPath).isEqualTo("/")
            get(ResponseCookie::isHttpOnly).isTrue()
            get(ResponseCookie::isSecure).isFalse()
            get(ResponseCookie::getSameSite).isEqualTo("Lax")
            get(ResponseCookie::getMaxAge).isEqualTo(Duration.ofDays(1))
        }
    }

    @Test
    fun `invalidates cookie`() {
        cookieService.invalidateCookie(exchange, COOKIE_NAME)

        val slot = slot<ResponseCookie>()
        verify(exactly = 1) { exchange.response.addCookie(capture(slot)) }
        expectThat(slot.captured) {
            get(ResponseCookie::getName).isEqualTo(COOKIE_NAME)
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

        val value = cookieService.decodeCookie(exchange.request, COOKIE_NAME)

        expectThat(value.blockOptional()) {
            get(Optional<String>::isEmpty).isTrue()
        }
    }

    @Test
    fun `decodes cookie from invalid exchange`() {
        every { exchange.request.cookies } returns CollectionUtils.toMultiValueMap(
            mapOf(COOKIE_NAME to listOf(HttpCookie(COOKIE_NAME, "something")))
        )

        val value = cookieService.decodeCookie(exchange.request, COOKIE_NAME)

        expectThat(value.blockOptional()) {
            get(Optional<String>::isEmpty).isTrue()
        }
    }

    @Test
    fun `decodes cookie from exchange`() {
        val encodedValue = cookieSerializer.encodeCookie(HOSTNAME, COOKIE_VALUE)
        every { exchange.request.cookies } returns CollectionUtils.toMultiValueMap(
            mapOf(COOKIE_NAME to listOf(HttpCookie(COOKIE_NAME, encodedValue)))
        )

        val value = cookieService.decodeCookie(exchange.request, COOKIE_NAME)

        expectThat(value.blockOptional()) {
            get(Optional<String>::isPresent).isTrue()
            get(Optional<String>::get).isEqualTo("value")
        }
    }

    @Test
    fun `decodes and cannot parse cookie from exchange`() {
        val encodedValue = cookieSerializer.encodeCookie(HOSTNAME, COOKIE_VALUE)
        every { exchange.request.cookies } returns CollectionUtils.toMultiValueMap(
            mapOf(COOKIE_NAME to listOf(HttpCookie(COOKIE_NAME, encodedValue)))
        )

        val value = cookieService.decodeCookie<OAuth2AuthorizationRequest>(exchange.request, COOKIE_NAME, mapper)

        expectThat(value.blockOptional()) {
            get(Optional<OAuth2AuthorizationRequest>::isEmpty).isTrue()
        }
    }

    @Test
    fun `decodes and parses cookie from exchange`() {
        val body = resource("mock_authorization_request.json").readText()
        every { exchange.request.cookies } returns CollectionUtils.toMultiValueMap(
            mapOf(COOKIE_NAME to listOf(HttpCookie(COOKIE_NAME, cookieSerializer.encodeCookie(HOSTNAME, body))))
        )

        val value = cookieService.decodeCookie<OAuth2AuthorizationRequest>(exchange.request, COOKIE_NAME, mapper)

        expectThat(value.blockOptional()) {
            get(Optional<OAuth2AuthorizationRequest>::isPresent).isTrue()
            get(Optional<OAuth2AuthorizationRequest>::get)
                .get(OAuth2AuthorizationRequest::getAuthorizationUri)
                .isEqualTo("authorizationUri")
        }
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

        @JvmStatic
        @BeforeAll
        fun init() {
            mockkStatic(::withOrganizationFromContext)
            every { withOrganizationFromContext() } returns Mono.just(Organization(ORG_ID))
        }
    }
}
