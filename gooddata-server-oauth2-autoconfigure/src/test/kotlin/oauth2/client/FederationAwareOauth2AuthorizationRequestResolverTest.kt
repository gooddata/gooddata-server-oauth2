/*
 * Copyright 2024 GoodData Corporation
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
package com.gooddata.oauth2.server.oauth2.client

import com.gooddata.oauth2.server.ReactiveCookieService
import com.gooddata.oauth2.server.SPRING_EXTERNAL_IDP
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.runs
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import reactor.core.publisher.Mono
import reactor.test.StepVerifier

@Suppress("ReactiveStreamsUnusedPublisher")
class FederationAwareOauth2AuthorizationRequestResolverTest {

    private val defaultResolver: ServerOAuth2AuthorizationRequestResolver = mockk {
        every { resolve(any()) } returns Mono.just(DEFAULT_AUTH_REQUEST)
        every { resolve(any(), any()) } returns Mono.just(DEFAULT_AUTH_REQUEST)
    }
    private val cookieService: ReactiveCookieService = mockk {
        every { decodeCookie(any(), any()) } returns Mono.empty()
        every { invalidateCookie(any(), any()) } just runs
    }

    private val resolver = FederationAwareOauth2AuthorizationRequestResolver(defaultResolver, cookieService)

    @Test
    fun `resolve without cookie`() {
        StepVerifier.create(oauthRequestToUri(resolver.resolve(EXCHANGE)))
            .expectNext("https://example.com/oauth2/authorize?response_type=code&client_id=client-id")
            .verifyComplete()
    }

    @Test
    fun `resolve with cookie and invalidates it`() {
        every { cookieService.decodeCookie(EXCHANGE, SPRING_EXTERNAL_IDP) } returns Mono.just("external-idp-id")

        StepVerifier.create(oauthRequestToUri(resolver.resolve(EXCHANGE)))
            .expectNext(
                "https://example.com/oauth2/authorize" +
                    "?response_type=code&client_id=client-id&idp_identifier=external-idp-id"
            )
            .verifyComplete()

        verify { cookieService.invalidateCookie(EXCHANGE, SPRING_EXTERNAL_IDP) }
    }

    @Test
    fun `resolve without cookie and client registration id`() {
        StepVerifier.create(oauthRequestToUri(resolver.resolve(EXCHANGE, "registration-id")))
            .expectNext("https://example.com/oauth2/authorize?response_type=code&client_id=client-id")
            .verifyComplete()
    }

    companion object {
        private val DEFAULT_AUTH_REQUEST = OAuth2AuthorizationRequest
            .authorizationCode()
            .authorizationUri("https://example.com/oauth2/authorize")
            .clientId("client-id")
            .build()

        private val EXCHANGE = MockServerWebExchange.from(
            MockServerHttpRequest.get("/oauth2/authorization/localhost")
        )

        private fun oauthRequestToUri(request: Mono<OAuth2AuthorizationRequest>): Mono<String> =
            request.map(OAuth2AuthorizationRequest::getAuthorizationRequestUri)
    }
}
