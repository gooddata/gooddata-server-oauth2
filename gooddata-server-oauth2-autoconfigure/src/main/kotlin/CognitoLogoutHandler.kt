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
package com.gooddata.oauth2.server

import mu.KotlinLogging
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.web.server.DefaultServerRedirectStrategy
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler
import org.springframework.web.util.UriComponentsBuilder
import reactor.core.publisher.Mono
import java.net.URI

/**
 * Realize logout if provider is Cognito
 * Inspired by https://auth0.com/docs/quickstart/webapp/java-spring-boot/01-login#add-logout-to-your-application
 * and https://rieckpil.de/oidc-logout-with-aws-cognito-and-spring-security/ with additional reference to
 * https://docs.aws.amazon.com/cognito/latest/developerguide/logout-endpoint.html
 *
 * @param clientRegistrationRepository the repository for client registrations
 * @param cognitoCustomDomain if defined, the Cognito is white-labeled by the custom domain name different
 * from the `*amazonaws.com`
 */
class CognitoLogoutHandler(
    private val clientRegistrationRepository: ReactiveClientRegistrationRepository,
    private val cognitoCustomDomain: String?,
) : ServerLogoutHandler, ServerLogoutSuccessHandler {

    private val logger = KotlinLogging.logger {}
    private val redirectStrategy = DefaultServerRedirectStrategy()

    override fun logout(exchange: WebFilterExchange, authentication: Authentication?): Mono<Void> =
        Mono.justOrEmpty(authentication)
            .filter { it is OAuth2AuthenticationToken }
            .cast(OAuth2AuthenticationToken::class.java)
            .flatMap {
                logoutUrl(exchange.exchange.request).flatMap { url ->
                    redirectStrategy.sendRedirect(exchange.exchange, url)
                }
            }

    override fun onLogoutSuccess(exchange: WebFilterExchange, authentication: Authentication): Mono<Void> =
        logout(exchange, authentication)

    private fun logoutUrl(request: ServerHttpRequest): Mono<URI> =
        clientRegistrationRepository.findByRegistrationId(request.uri.host)
            .map { clientRegistration ->
                Pair(clientRegistration, clientRegistration.issuer())
            }.filter { (_, issuer) ->
                issuer.isCognito() || issuer.hasCustomDomain()
            }.map { (clientRegistration) ->
                // workaround for STL-458: use URL from 'returnTo' query parameter if provided,
                // otherwise use default URL
                val returnTo = URI.create(request.returnToQueryParam()) ?: request.uri.baseUrl()
                buildLogoutUrl(
                    clientRegistration.endSessionEndpoint(),
                    clientRegistration.clientId,
                    returnTo
                )
            }.doOnNext { logoutUrl ->
                logger.debug { "Cognito logout URL: $logoutUrl" }
            }

    private fun ClientRegistration.issuer(): URI = providerDetails.configurationMetadata["issuer"].toString().toUri()

    private fun ClientRegistration.endSessionEndpoint(): URI = providerDetails
        .configurationMetadata["end_session_endpoint"].toString().toUri()

    private fun URI.hasCustomDomain(): Boolean = cognitoCustomDomain != null && cognitoCustomDomain == host

    private fun buildLogoutUrl(endSessionEndpoint: URI, clientId: String, logoutUri: URI): URI =
        UriComponentsBuilder
            .fromUri(endSessionEndpoint)
            .queryParam("client_id", clientId)
            .queryParam("logout_uri", logoutUri)
            .build()
            .toUri()
}
