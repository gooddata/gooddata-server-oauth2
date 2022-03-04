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
package com.gooddata.oauth2.server.reactive

import io.mockk.mockk
import org.junit.jupiter.api.Test
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.security.web.server.WebFilterExchange
import strikt.api.expectThat
import strikt.assertions.containsKey
import strikt.assertions.isEqualTo

class ServerOAuth2FailureHandlerTest {

    private val handler: ServerOAuth2FailureHandler = ServerOAuth2FailureHandler()

    @Test
    fun `on authentication failure response with message is set`() {
        val request = MockServerHttpRequest.get(
            "http://localhost:9050/login/oauth2/code/goodcommunity.stg11.intgdc.com?" +
                "state=123&error=access_denied&error_description=User+is+not+assigned+to+the+client+application."
        ).build()
        val exchange = WebFilterExchange(MockServerWebExchange.builder(request).build(), mockk(relaxed = true))

        handler.onAuthenticationFailure(exchange, mockk(relaxed = true))

        expectThat(exchange.exchange.response) {
            get { statusCode }.isEqualTo(HttpStatus.UNAUTHORIZED)
            get { headers }.containsKey(HttpHeaders.WWW_AUTHENTICATE)
            get { headers.toSingleValueMap()[HttpHeaders.WWW_AUTHENTICATE] }
                .isEqualTo("Unable to authenticate: access_denied: User is not assigned to the client application.")
        }
    }

    @Test
    fun `on authentication failure response with default message is set`() {
        val request = MockServerHttpRequest.get(
            "http://localhost:9050/login/oauth2/code/goodcommunity.stg11.intgdc.com?state=123&error=access_denied"
        ).build()
        val exchange = WebFilterExchange(MockServerWebExchange.builder(request).build(), mockk(relaxed = true))

        handler.onAuthenticationFailure(exchange, mockk(relaxed = true))

        expectThat(exchange.exchange.response) {
            get { statusCode }.isEqualTo(HttpStatus.UNAUTHORIZED)
            get { headers }.containsKey(HttpHeaders.WWW_AUTHENTICATE)
            get { headers.toSingleValueMap()[HttpHeaders.WWW_AUTHENTICATE] }
                .isEqualTo("Unable to authenticate: access_denied: Authentication failed")
        }
    }
}
