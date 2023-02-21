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

import mu.KotlinLogging
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

/**
 * Refreshes OIDC tokens if the refresh token is available. OIDC tokens which can be refreshed:
 * * Refresh Token itself
 * * Access Token
 * * ID Token if provided by the "Refresh Flow" of the IdP
 *
 * The service works with the [ServerOAuth2AuthorizedClientRepository], which means that it gets the refresh token
 * and saves refreshed OAuth2 client tokens (Access/Refresh) into that repository.
 *
 * @param refreshTokenResponseClient reactive web client for calling refresh API of the IdP
 * @param authorizedClientRepository the repository containing OAuth2 client tokens
 */
class RepositoryAwareOidcTokensRefreshingService(
    private val refreshTokenResponseClient: ReactiveOAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest>,
    private val authorizedClientRepository: ServerOAuth2AuthorizedClientRepository,
) {
    private val logger = KotlinLogging.logger {}

    /**
     * Gracefully tries to refresh all OIDC tokens and returns them. In the case of not successful refresh,
     * the function ends with empty result. The refresh is not successful, when:
     * * [authorizedClientRepository] does not contain any refresh token
     * * [refreshTokenResponseClient] responds with the empty result
     * * [refreshTokenResponseClient] responds with a failure which is just logged and translated into the empty result.
     *
     * As a side effect, OAuth2 client tokens from the successful [refreshTokenResponseClient] response are saved
     * into [authorizedClientRepository] because the old tokens are not valid anymore after the refresh.
     *
     * @param clientRegistration the OAuth2 client registration metadata
     * @param oauthToken the OAuth2 authentication principal
     * @param exchange the web exchange
     * @return [Mono] providing the refresh response with new OIDC tokens
     */
    fun refreshTokensIfPossible(
        clientRegistration: ClientRegistration,
        oauthToken: OAuth2AuthenticationToken,
        exchange: ServerWebExchange,
    ): Mono<OAuth2AccessTokenResponse> = authorizedClientRepository
        .loadAuthorizedClient<OAuth2AuthorizedClient>(clientRegistration.registrationId, oauthToken, exchange)
        .filter { authClient -> authClient.refreshToken != null }
        .flatMap { authClient ->
            val refreshTokenRequest = OAuth2RefreshTokenGrantRequest(
                clientRegistration,
                authClient.accessToken,
                authClient.refreshToken,
                clientRegistration.scopes
            )
            refreshTokenResponseClient.getTokenResponse(refreshTokenRequest)
                .flatMap { tokenResponse ->
                    val authorizedClient = OAuth2AuthorizedClient(
                        clientRegistration,
                        authClient.principalName,
                        tokenResponse.accessToken,
                        tokenResponse.refreshToken
                    )
                    // save new tokens into repository
                    authorizedClientRepository
                        .saveAuthorizedClient(authorizedClient, oauthToken, exchange)
                        .then(Mono.just(tokenResponse))
                }
                .onErrorResume { exception ->
                    logger.info(exception) {
                        "Unable to refresh tokens for the principal '${authClient.principalName}'" +
                            " in the client registration ${clientRegistration.registrationId}."
                    }
                    Mono.empty()
                }
        }
}
