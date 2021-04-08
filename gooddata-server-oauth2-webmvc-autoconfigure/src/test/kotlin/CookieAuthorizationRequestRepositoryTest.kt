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
import com.gooddata.oauth2.server.common.SPRING_SEC_OAUTH2_AUTHZ_RQ
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
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import strikt.api.expectThat
import strikt.assertions.isEqualTo
import strikt.assertions.isNotNull
import strikt.assertions.isNull
import java.time.Duration
import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

internal class CookieAuthorizationRequestRepositoryTest {
    private val properties = CookieServiceProperties(Duration.ofDays(1), CookieHeaderNames.SameSite.Lax, "")

    private val cookieSerializer = CookieSerializer(properties)

    private val cookieService = spyk(CookieService(properties, cookieSerializer))

    private val request: HttpServletRequest = mockk()

    private val response: HttpServletResponse = mockk()

    private val repository = CookieAuthorizationRequestRepository(cookieService)

    @Test
    fun `should not load request when nothing is stored in cookies`() {
        every { request.cookies } returns emptyArray()

        val authRequest = repository.loadAuthorizationRequest(request)

        expectThat(authRequest).isNull()
    }

    @Test
    fun `should not load request when nonsense is stored in cookies`() {
        every { request.cookies } returns arrayOf(Cookie(SPRING_SEC_OAUTH2_AUTHZ_RQ, "something"))

        val authRequest = repository.loadAuthorizationRequest(request)

        expectThat(authRequest).isNull()
    }

    @Test
    fun `should load request from cookie`() {
        val body = resource("oauth2_authorization_request.json").readText()
        every { request.cookies } returns arrayOf(
            Cookie(SPRING_SEC_OAUTH2_AUTHZ_RQ, cookieSerializer.encodeCookie(body))
        )

        val authRequest = repository.loadAuthorizationRequest(request)

        expectThat(authRequest) {
            isNotNull()
                .get(OAuth2AuthorizationRequest::getAuthorizationUri)
                .isEqualTo("https://dev-6-eq6djb.eu.auth0.com/authorize")
        }
    }

    @Test
    fun `should save request`() {
        val authRequest = OAuth2AuthorizationRequest.authorizationCode()
            .authorizationUri("authorizationUri")
            .clientId("clientId")
            .build()

        val slot = slot<String>()
        every { cookieService.createCookie(any(), any(), any(), capture(slot)) } returns Unit

        repository.saveAuthorizationRequest(authRequest, request, response)

        // none for invalid content, one for terminal
        verify(exactly = 1) { cookieService.createCookie(request, response, SPRING_SEC_OAUTH2_AUTHZ_RQ, any()) }

        assertJsonEquals(
            resource("mock_authorization_request.json").readText(),
            slot.captured,
            Configuration.empty().withOptions(Option.IGNORING_ARRAY_ORDER)
        )
    }

    @Test
    fun `should remove request from cookies`() {
        every { request.cookies } returns arrayOf(Cookie(SPRING_SEC_OAUTH2_AUTHZ_RQ, "some invalid content"))
        every { cookieService.invalidateCookie(any(), any(), any()) } returns Unit

        val authRequest = repository.removeAuthorizationRequest(request, response)
        expectThat(authRequest).isNull()

        verify(exactly = 1) { cookieService.invalidateCookie(request, response, SPRING_SEC_OAUTH2_AUTHZ_RQ) }
    }

    @Test
    fun `should remove request if there is some problem reading it`() {
        val body = resource("oauth2_authorization_request.json").readText()
        every { request.cookies } returns arrayOf(
            Cookie(SPRING_SEC_OAUTH2_AUTHZ_RQ, cookieSerializer.encodeCookie(body))
        )
        every { cookieService.invalidateCookie(any(), any(), any()) } returns Unit

        val authRequest = repository.removeAuthorizationRequest(request, response)

        expectThat(authRequest) {
            isNotNull()
                .get(OAuth2AuthorizationRequest::getAuthorizationUri)
                .isEqualTo("https://dev-6-eq6djb.eu.auth0.com/authorize")
        }

        verify(exactly = 1) { cookieService.invalidateCookie(request, response, SPRING_SEC_OAUTH2_AUTHZ_RQ) }
    }
}
