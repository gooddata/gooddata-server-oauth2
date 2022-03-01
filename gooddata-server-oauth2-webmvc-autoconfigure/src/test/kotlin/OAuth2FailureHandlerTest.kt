/*
 * Copyright 2022 GoodData Corporation
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

import io.mockk.mockk
import org.apache.http.client.methods.HttpGet
import org.junit.jupiter.api.Test
import org.springframework.http.HttpHeaders
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import strikt.api.expectThat
import strikt.assertions.contains
import strikt.assertions.isEqualTo
import javax.servlet.http.HttpServletResponse

class OAuth2FailureHandlerTest {

    private val handler: OAuth2FailureHandler = OAuth2FailureHandler()

    @Test
    fun `on authentication failure response with message is set`() {
        val request = MockHttpServletRequest(
            HttpGet.METHOD_NAME,
            "http://localhost:9050/login/oauth2/code/goodcommunity.stg11.intgdc.com"
        )
        request.queryString =
            "state=123&error=access_denied&error_description=User+is+not+assigned+to+the+client+application."
        val response = MockHttpServletResponse()

        handler.onAuthenticationFailure(request, response, mockk(relaxed = true))

        expectThat(response) {
            get { status }.isEqualTo(HttpServletResponse.SC_UNAUTHORIZED)
            get { headerNames }.contains(HttpHeaders.WWW_AUTHENTICATE)
            get { getHeaderValue(HttpHeaders.WWW_AUTHENTICATE) }
                .isEqualTo("Unable to authenticate: access_denied: User is not assigned to the client application.")
        }
    }

    @Test
    fun `on authentication failure response with default message is set`() {
        val request = MockHttpServletRequest(
            HttpGet.METHOD_NAME,
            "http://localhost:9050/login/oauth2/code/goodcommunity.stg11.intgdc.com"
        )
        request.queryString = "state=123&error=access_denied"
        val response = MockHttpServletResponse()

        handler.onAuthenticationFailure(request, response, mockk(relaxed = true))

        expectThat(response) {
            get { status }.isEqualTo(HttpServletResponse.SC_UNAUTHORIZED)
            get { headerNames }.contains(HttpHeaders.WWW_AUTHENTICATE)
            get { getHeaderValue(HttpHeaders.WWW_AUTHENTICATE) }
                .isEqualTo("Unable to authenticate: access_denied: Authentication failed")
        }
    }
}
