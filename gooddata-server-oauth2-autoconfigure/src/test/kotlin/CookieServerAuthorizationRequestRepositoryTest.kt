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
import net.javacrumbs.jsonunit.JsonAssert.assertJsonEquals
import net.javacrumbs.jsonunit.core.Configuration
import net.javacrumbs.jsonunit.core.Option
import net.javacrumbs.jsonunit.core.util.ResourceUtils.resource
import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.Test
import org.springframework.http.HttpCookie
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.util.CollectionUtils.toMultiValueMap
import org.springframework.web.server.ServerWebExchange
import strikt.api.expectThat
import strikt.assertions.isEqualTo
import strikt.assertions.isTrue
import java.net.URI
import java.time.Duration
import java.time.Instant
import java.util.Optional

internal class CookieServerAuthorizationRequestRepositoryTest {
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

    private val exchange: ServerWebExchange = mockk()

    private val cookieService = spyk(ReactiveCookieService(properties, cookieSerializer))

    private val repository = CookieServerAuthorizationRequestRepository(cookieService)

    @Test
    fun `should not load request when nothing is stored in cookies`() {
        every { exchange.request.uri } returns URI.create("http://localhost")
        every { exchange.request.cookies } returns toMultiValueMap(emptyMap())

        val request = repository.loadAuthorizationRequest(exchange)

        expectThat(request.blockOptional()) {
            get(Optional<OAuth2AuthorizationRequest>::isEmpty).isTrue()
        }
    }

    @Test
    fun `should not load request when nonsense is stored in cookies`() {
        every { exchange.request.uri } returns URI.create("http://localhost")
        every { exchange.request.cookies } returns toMultiValueMap(
            mapOf(SPRING_SEC_OAUTH2_AUTHZ_RQ to listOf(HttpCookie(SPRING_SEC_OAUTH2_AUTHZ_RQ, "something")))
        )

        val request = repository.loadAuthorizationRequest(exchange)

        expectThat(request.blockOptional()) {
            get(Optional<OAuth2AuthorizationRequest>::isEmpty).isTrue()
        }
    }

    @Test
    fun `should load request from cookie`() {
        val body = resource("oauth2_authorization_request.json").readText()

        every { exchange.request.uri } returns URI.create("http://localhost")
        every { exchange.request.cookies } returns toMultiValueMap(
            mapOf(
                SPRING_SEC_OAUTH2_AUTHZ_RQ to listOf(
                    HttpCookie(SPRING_SEC_OAUTH2_AUTHZ_RQ, cookieSerializer.encodeCookie("localhost", body))
                )
            )
        )

        val request = repository.loadAuthorizationRequest(exchange).blockOptional().get()

        expectThat(request) {
            get(OAuth2AuthorizationRequest::getAuthorizationUri)
                .isEqualTo("https://localhost/authorize")
        }
    }

    @Test
    fun `should save request`() {
        val request = OAuth2AuthorizationRequest.authorizationCode()
            .authorizationUri("authorizationUri")
            .clientId("clientId")
            .build()

        val slot = slot<String>()
        every { cookieService.createCookie(any(), any(), capture(slot)) } returns Unit

        val response = repository.saveAuthorizationRequest(request, exchange)
        expectThat(response.blockOptional()) {
            get(Optional<Void>::isEmpty).isTrue()
        }

        // none for invalid content, one for terminal
        verify(exactly = 1) { cookieService.createCookie(exchange, SPRING_SEC_OAUTH2_AUTHZ_RQ, any()) }

        assertJsonEquals(
            resource("mock_authorization_request.json").readText(),
            slot.captured,
            Configuration.empty().withOptions(Option.IGNORING_ARRAY_ORDER)
        )
    }

    @Test
    fun `should remove request from cookies`() {
        every { exchange.request.uri } returns URI.create("http://localhost")
        every { exchange.request.cookies } returns toMultiValueMap(
            mapOf(SPRING_SEC_OAUTH2_AUTHZ_RQ to listOf(HttpCookie(SPRING_SEC_OAUTH2_AUTHZ_RQ, "some invalid content")))
        )
        every { cookieService.invalidateCookie(any(), any()) } returns Unit

        val request = repository.removeAuthorizationRequest(exchange)
        expectThat(request.blockOptional()) {
            get(Optional<OAuth2AuthorizationRequest>::isEmpty).isTrue()
        }

        // none for invalid content, one for terminal
        verify(exactly = 1) { cookieService.invalidateCookie(exchange, SPRING_SEC_OAUTH2_AUTHZ_RQ) }
    }

    @Test
    fun `should remove request if there is some problem reading it`() {
        val body = resource("oauth2_authorization_request.json").readText()
        every { exchange.request.uri } returns URI.create("http://localhost")
        every { exchange.request.cookies } returns toMultiValueMap(
            mapOf(
                SPRING_SEC_OAUTH2_AUTHZ_RQ to listOf(
                    HttpCookie(SPRING_SEC_OAUTH2_AUTHZ_RQ, cookieSerializer.encodeCookie("localhost", body))
                )
            )
        )
        every { cookieService.invalidateCookie(any(), any()) } returns Unit

        val request = repository.removeAuthorizationRequest(exchange).blockOptional().get()

        expectThat(request) {
            get(OAuth2AuthorizationRequest::getAuthorizationUri)
                .isEqualTo("https://localhost/authorize")
        }

        // one for loaded request, one for terminal
        verify(exactly = 2) { cookieService.invalidateCookie(exchange, SPRING_SEC_OAUTH2_AUTHZ_RQ) }
    }
}
