/*
 * Copyright 2023 GoodData Corporation
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

import io.mockk.Called
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse
import reactor.core.publisher.Mono
import strikt.api.expectThat
import strikt.assertions.isEqualTo
import strikt.assertions.isNotNull
import strikt.assertions.isTrue
import java.time.Instant

internal class RepositoryAwareOidcTokensRefreshingServiceTest {

    private val refreshTokenResponseClient =
        mockk<ReactiveOAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest>>()
    private val authorizedClientRepository = mockk<ServerOAuth2AuthorizedClientRepository>()
    private val refreshService = RepositoryAwareOidcTokensRefreshingService(
        refreshTokenResponseClient,
        authorizedClientRepository,
    )

    @Test
    fun `refreshes tokens`() {
        val newAccessToken = "newAccessToken123"
        val newRefreshToken = "newRefreshToken123"
        val refreshResponse = OAuth2AccessTokenResponse
            .withToken(newAccessToken)
            .refreshToken(newRefreshToken)
            .tokenType(OAuth2AccessToken.TokenType.BEARER)
            .build()

        every {
            authorizedClientRepository.loadAuthorizedClient<OAuth2AuthorizedClient>(any(), any(), any())
        } returns Mono.just(OLD_OAUTH2_CLIENT)
        every { authorizedClientRepository.saveAuthorizedClient(any(), any(), any()) } returns Mono.empty()
        every { refreshTokenResponseClient.getTokenResponse(any()) } returns Mono.just(refreshResponse)

        val refreshedTokens = refreshService.refreshTokensIfPossible(CLIENT_REGISTRATION, mockk(), EXCHANGE).block()

        val refreshRequest = slot<OAuth2RefreshTokenGrantRequest>()
        val newOAuth2Client = slot<OAuth2AuthorizedClient>()
        verify {
            refreshTokenResponseClient.getTokenResponse(capture(refreshRequest))
            authorizedClientRepository.saveAuthorizedClient(capture(newOAuth2Client), any(), any())
        }
        expectThat(refreshRequest.captured) {
            get { accessToken }.isEqualTo(OLD_ACCESS_TOKEN)
            get { refreshToken }.isEqualTo(OLD_REFRESH_TOKEN)
        }
        expectThat(newOAuth2Client.captured) {
            get { accessToken?.tokenValue }.isEqualTo(newAccessToken)
            get { refreshToken?.tokenValue }.isEqualTo(newRefreshToken)
        }
        expectThat(refreshedTokens).isNotNull().and {
            get { accessToken?.tokenValue }.isEqualTo(newAccessToken)
            get { refreshToken?.tokenValue }.isEqualTo(newRefreshToken)
        }
    }

    @Test
    fun `does not refresh tokens when no token in repository`() {
        every {
            authorizedClientRepository.loadAuthorizedClient<OAuth2AuthorizedClient>(any(), any(), any())
        } returns Mono.empty()
        verifyEmptyRefresh()
        verify { refreshTokenResponseClient wasNot Called }
    }

    private fun verifyEmptyRefresh() {
        val refreshedTokens =
            refreshService.refreshTokensIfPossible(CLIENT_REGISTRATION, mockk(), EXCHANGE).blockOptional()

        verify(exactly = 0) { authorizedClientRepository.saveAuthorizedClient(any(), any(), any()) }
        expectThat(refreshedTokens).get { isEmpty }.isTrue()
    }

    @Test
    fun `does not refresh tokens when no refresh token provided`() {
        every {
            authorizedClientRepository.loadAuthorizedClient<OAuth2AuthorizedClient>(any(), any(), any())
        } returns Mono.just(
            OAuth2AuthorizedClient(
                CLIENT_REGISTRATION,
                PRINCIPAL_NAME,
                OLD_ACCESS_TOKEN,
            )
        )

        verifyEmptyRefresh()
        verify { refreshTokenResponseClient wasNot Called }
    }

    @Test
    fun `does not refresh tokens when refresh response is empty`() {
        every {
            authorizedClientRepository.loadAuthorizedClient<OAuth2AuthorizedClient>(any(), any(), any())
        } returns Mono.just(OLD_OAUTH2_CLIENT)
        every { refreshTokenResponseClient.getTokenResponse(any()) } returns Mono.empty()

        verifyEmptyRefresh()
    }

    @Test
    fun `does not refresh tokens when fails refreshing`() {
        every {
            authorizedClientRepository.loadAuthorizedClient<OAuth2AuthorizedClient>(any(), any(), any())
        } returns Mono.just(OLD_OAUTH2_CLIENT)
        every { refreshTokenResponseClient.getTokenResponse(any()) } returns Mono.error(RuntimeException("an error"))

        verifyEmptyRefresh()
    }

    companion object {
        private val EXCHANGE = MockServerWebExchange.from(MockServerHttpRequest.get("/dummy")).apply {
            putOrganizationAttribute(Organization("org123"))
        }
        private val CLIENT_REGISTRATION = mockk<ClientRegistration>(relaxed = true) {
            every { registrationId } returns "id123"
        }
        private const val PRINCIPAL_NAME = "user.123"
        private val OLD_ACCESS_TOKEN = OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            "oldAccessToken123",
            Instant.parse("2023-02-20T10:15:30.00Z"),
            Instant.parse("2023-02-21T10:15:30.00Z"),
        )
        private val OLD_REFRESH_TOKEN = OAuth2RefreshToken(
            "oldRefreshToken123",
            Instant.parse("2023-02-20T10:15:30.00Z"),
            Instant.parse("2023-10-20T10:15:30.00Z"),
        )
        private val OLD_OAUTH2_CLIENT = OAuth2AuthorizedClient(
            CLIENT_REGISTRATION,
            PRINCIPAL_NAME,
            OLD_ACCESS_TOKEN,
            OLD_REFRESH_TOKEN,
        )
    }
}
