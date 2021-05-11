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
import com.gooddata.oauth2.server.common.SPRING_SEC_SECURITY_CONTEXT
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
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.ClientRegistrations
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority
import org.springframework.security.web.context.HttpRequestResponseHolder
import strikt.api.expectThat
import strikt.assertions.isA
import strikt.assertions.isEqualTo
import strikt.assertions.isNull
import java.time.Duration
import java.time.Instant
import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

internal class CookieSecurityContextRepositoryTest {

    private val clientRegistrationRepository: ClientRegistrationRepository = mockk()

    private val properties = CookieServiceProperties(Duration.ofDays(1), CookieHeaderNames.SameSite.Lax, "")

    private val cookieSerializer = CookieSerializer(properties)

    private val cookieService = spyk(CookieService(properties, cookieSerializer))

    private val request: HttpServletRequest = mockk()

    private val response: HttpServletResponse = mockk()

    private val repository = CookieSecurityContextRepository(clientRegistrationRepository, cookieService)

    @Test
    fun `should save context`() {
        val idToken = OidcIdToken(
            "tokenValue", Instant.EPOCH, Instant.EPOCH.plusSeconds(1), mapOf(IdTokenClaimNames.SUB to null)
        )
        val context = SecurityContextImpl(
            OAuth2AuthenticationToken(
                DefaultOidcUser(
                    listOf(OidcUserAuthority(idToken)),
                    idToken
                ),
                emptyList(),
                "registrationId"
            )
        )
        val slot = slot<String>()
        every { cookieService.createCookie(any(), any(), any(), capture(slot)) } returns Unit

        repository.saveContext(context, request, response)

        verify(exactly = 1) { cookieService.createCookie(request, response, SPRING_SEC_SECURITY_CONTEXT, any()) }

        assertJsonEquals(
            resource("mock_authentication_token.json").readText(),
            slot.captured,
            Configuration.empty().withOptions(Option.IGNORING_ARRAY_ORDER)
        )
    }

    @Test
    fun `should remove context from cookies`() {
        every { cookieService.invalidateCookie(any(), any(), any()) } returns Unit

        repository.saveContext(SecurityContextImpl(), request, response)

        verify(exactly = 1) { cookieService.invalidateCookie(request, response, SPRING_SEC_SECURITY_CONTEXT) }
    }

    @Test
    fun `should not load context when nothing is stored in cookies`() {
        every { request.cookies } returns emptyArray()

        val context = repository.loadContext(HttpRequestResponseHolder(request, response))

        expectThat(context) {
            get(SecurityContext::getAuthentication).isNull()
        }
    }

    @Test
    fun `should not load context when nonsense is stored in cookies`() {
        every { request.cookies } returns arrayOf(Cookie(SPRING_SEC_SECURITY_CONTEXT, "something"))

        val context = repository.loadContext(HttpRequestResponseHolder(request, response))

        expectThat(context) {
            get(SecurityContext::getAuthentication).isNull()
        }
    }

    @Test
    fun `should not load context from cookie if registration id is not mapped`() {
        val body = resource("oauth2_authentication_token.json").readText()
        every { request.cookies } returns arrayOf(
            Cookie(SPRING_SEC_SECURITY_CONTEXT, cookieSerializer.encodeCookie(body))
        )
        every { clientRegistrationRepository.findByRegistrationId(any()) } returns null

        val context = repository.loadContext(HttpRequestResponseHolder(request, response))

        expectThat(context) {
            get(SecurityContext::getAuthentication).isNull()
        }
    }

    @Test
    fun `should load context from cookie`() {
        val body = resource("oauth2_authentication_token.json").readText()
        every { request.cookies } returns arrayOf(
            Cookie(SPRING_SEC_SECURITY_CONTEXT, cookieSerializer.encodeCookie(body))
        )
        every { clientRegistrationRepository.findByRegistrationId(any()) } returns ClientRegistrations
            .fromIssuerLocation("https://dev-6-eq6djb.eu.auth0.com/")
            .registrationId("localhost")
            .clientId("zB85JfotOTabIdSAqsIWPj6ZV4tCXaHD")
            .build()

        val context = repository.loadContext(HttpRequestResponseHolder(request, response))

        expectThat(context.authentication) {
            isA<OAuth2AuthenticationToken>()
                .get(OAuth2AuthenticationToken::getAuthorizedClientRegistrationId)
                .isEqualTo("localhost")
        }
    }
}
