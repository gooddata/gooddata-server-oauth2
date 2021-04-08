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

import com.gooddata.oauth2.server.common.CookieSerializer
import com.gooddata.oauth2.server.common.CookieServiceProperties
import com.gooddata.oauth2.server.common.SPRING_SEC_OAUTH2_AUTHZ_CLIENT
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
import org.junit.jupiter.api.Test
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.ClientRegistrations
import org.springframework.security.oauth2.core.OAuth2AccessToken
import strikt.api.expectThat
import strikt.api.expectThrows
import strikt.assertions.isEqualTo
import strikt.assertions.isNotNull
import strikt.assertions.isNull
import java.time.Duration
import java.time.Instant
import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

internal class CookieOAuth2AuthorizedClientRepositoryTest {

    private val clientRegistrationRepository: ClientRegistrationRepository = mockk()

    private val properties = CookieServiceProperties(Duration.ofDays(1), CookieHeaderNames.SameSite.Lax, "")

    private val cookieSerializer = CookieSerializer(properties)

    private val cookieService = spyk(CookieService(properties, cookieSerializer))

    private val principal: Authentication = mockk()

    private val request: HttpServletRequest = mockk()

    private val response: HttpServletResponse = mockk()

    private val repository = CookieOAuth2AuthorizedClientRepository(clientRegistrationRepository, cookieService)

    @Test
    fun `should not load client when nothing is stored in cookies`() {
        every { request.cookies } returns emptyArray()

        val client = repository.loadAuthorizedClient<OAuth2AuthorizedClient>(
            "registrationId", principal, request
        )

        expectThat(client).isNull()
    }

    @Test
    fun `should not load client when nonsense is stored in cookies`() {
        every { request.cookies } returns arrayOf(Cookie(SPRING_SEC_OAUTH2_AUTHZ_CLIENT, "something"))

        val client = repository.loadAuthorizedClient<OAuth2AuthorizedClient>(
            "registrationId", principal, request
        )

        expectThat(client).isNull()
    }

    @Test
    fun `should not load client from cookie if registration id does not match`() {
        val body = resource("simplified_oauth2_authorized_client.json").readText()
        every { request.cookies } returns arrayOf(
            Cookie(
                SPRING_SEC_OAUTH2_AUTHZ_CLIENT,
                cookieSerializer.encodeCookie(body),
            )
        )

        expectThrows<IllegalStateException> {
            repository.loadAuthorizedClient<OAuth2AuthorizedClient>(
                "registrationId", principal, request
            )
        }
    }

    @Test
    fun `should load client from cookie`() {
        val body = resource("simplified_oauth2_authorized_client.json").readText()
        every { request.cookies } returns arrayOf(
            Cookie(
                SPRING_SEC_OAUTH2_AUTHZ_CLIENT,
                cookieSerializer.encodeCookie(body),
            )
        )
        every { clientRegistrationRepository.findByRegistrationId(any()) } returns ClientRegistrations
            .fromIssuerLocation("https://dev-6-eq6djb.eu.auth0.com/")
            .registrationId("localhost")
            .clientId("clientId")
            .build()

        val client = repository.loadAuthorizedClient<OAuth2AuthorizedClient>(
            "localhost", principal, request
        )

        expectThat(client) {
            isNotNull()
                .get(OAuth2AuthorizedClient::getPrincipalName)
                .isEqualTo("auth0|5f6dee2c5924f0006f077df0")
        }
    }

    @Test
    fun `should save client`() {
        val client = OAuth2AuthorizedClient(
            ClientRegistrations
                .fromIssuerLocation("https://dev-6-eq6djb.eu.auth0.com/")
                .registrationId("localhost")
                .clientId("clientId")
                .build(),
            "principalName",
            OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "value", Instant.EPOCH, Instant.EPOCH.plusSeconds(1))
        )

        val slot = slot<String>()
        every { cookieService.createCookie(any(), any(), any(), capture(slot)) } returns Unit

        repository.saveAuthorizedClient(client, principal, request, response)

        verify(exactly = 1) { cookieService.createCookie(request, response, SPRING_SEC_OAUTH2_AUTHZ_CLIENT, any()) }

        assertJsonEquals(
            resource("mock_authorized_client.json").readText(),
            slot.captured,
            Configuration.empty().withOptions(Option.IGNORING_ARRAY_ORDER)
        )
    }

    @Test
    fun `should remove client from cookies`() {
        every { cookieService.invalidateCookie(any(), any(), any()) } returns Unit

        repository.removeAuthorizedClient("registrationId", principal, request, response)

        verify(exactly = 1) { cookieService.invalidateCookie(request, response, SPRING_SEC_OAUTH2_AUTHZ_CLIENT) }
    }
}
