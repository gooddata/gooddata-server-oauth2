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

import io.github.oshai.kotlinlogging.KLogger
import io.github.oshai.kotlinlogging.KotlinLogging
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
        .flatMap { authClient -> getRefreshTokenOrEmpty(authClient, exchange) }
        .flatMap { authClient -> doRefresh(clientRegistration, authClient, oauthToken, exchange) }

    /**
     * Retrieves a refresh token from the provided OAuth2AuthorizedClient if it exists; otherwise,
     * returns an empty Mono.
     *
     * @param authClient the OAuth2 client containing authentication and token details
     * @param exchange the web exchange providing request-specific context
     * @return a Mono containing the OAuth2AuthorizedClient if a refresh token is available; otherwise, an empty Mono
     */
    private fun getRefreshTokenOrEmpty(
        authClient: OAuth2AuthorizedClient,
        exchange: ServerWebExchange,
    ) = if (authClient.refreshToken != null) {
        logger.logRefresh(exchange, authClient) {
            withState("start")
            withMessage { "Refreshing session with existing refresh token" }
        }
        Mono.just(authClient)
    } else {
        logger.logRefresh(exchange, authClient) {
            withState("skip")
            withMessage { "No refresh token found in session tokens" }
        }
        Mono.empty()
    }

    /**
     * Attempts to refresh OAuth2 tokens for the provided client registration and authorized client.
     * If successful, new tokens are saved into the authorized client repository.
     * In case of an error, the process logs the failure and returns an empty result.
     *
     * @param clientRegistration the metadata of the OAuth2 client registration
     * @param authClient the OAuth2 authorized client containing the existing token details
     * @param oauthToken the OAuth2 authentication token representing the authenticated principal
     * @param exchange the server web exchange providing the current request-specific context
     * @return a Mono emitting an [OAuth2AccessTokenResponse] with refreshed tokens if successful,
     *         or an empty Mono if the refresh fails
     */
    private fun doRefresh(
        clientRegistration: ClientRegistration,
        authClient: OAuth2AuthorizedClient,
        oauthToken: OAuth2AuthenticationToken,
        exchange: ServerWebExchange,
    ): Mono<OAuth2AccessTokenResponse> {
        val refreshTokenRequest = OAuth2RefreshTokenGrantRequest(
            clientRegistration,
            authClient.accessToken,
            authClient.refreshToken,
            clientRegistration.scopes
        )
        return refreshTokenResponseClient.getTokenResponse(refreshTokenRequest)
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
            .doOnNext { tokenResponse ->
                logger.logRefresh(exchange, authClient) {
                    withState("finish")
                    withMessage {
                        if (tokenResponse.refreshToken == null) {
                            "Refreshed session tokens with new" +
                                " access token (expiry: ${tokenResponse.accessToken.expiresAt}) only."
                        } else {
                            "Refreshed session tokens with new" +
                                " refresh token (expiry: ${tokenResponse.refreshToken!!.expiresAt})" +
                                " and access token (expiry: ${tokenResponse.accessToken.expiresAt})."
                        }
                    }
                }
            }
            .onErrorResume { exception ->
                logger.logRefresh(exchange, authClient) {
                    withState("error")
                    withException(exception)
                    withMessage {
                        "Unable to refresh tokens in the client registration ${clientRegistration.registrationId}."
                    }
                }
                Mono.empty()
            }
    }

    companion object {
        private const val REFRESH_ACTION = "session_refresh"

        /**
         * Logs a refresh action for OAuth2 tokens with additional contextual information.
         *
         * @param exchange the server web exchange providing request-specific context
         * @param authClient the OAuth2 authorized client containing authentication and token details
         * @param block additional configuration block for building the log message
         */
        private fun KLogger.logRefresh(
            exchange: ServerWebExchange,
            authClient: OAuth2AuthorizedClient,
            block: LogBuilder.() -> Unit
        ) {
            logInfo {
                withOrganizationId(exchange.maybeOrganizationFromAttributes()?.id)
                withAuthenticationId(authClient.principalName)
                withAction(REFRESH_ACTION)
                block()
            }
        }
    }
}
