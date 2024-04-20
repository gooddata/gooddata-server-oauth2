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
package com.gooddata.oauth2.server

import com.gooddata.oauth2.server.jackson.SimplifiedOAuth2AuthorizedClient
import com.gooddata.oauth2.server.jackson.mapper
import com.gooddata.oauth2.server.jackson.toSimplified
import java.time.Instant
import mu.KotlinLogging
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

/**
 * Implementation of [ServerOAuth2AuthorizedClientRepository] that stores [OAuth2AuthorizedClient] into
 * `SPRING_SEC_OAUTH2_AUTHZ_CLIENT` HTTP cookie.
 * [org.springframework.security.oauth2.client.registration.ClientRegistration] is not stored there and is loaded
 * from [ReactiveClientRegistrationRepository] based on stored clientRegistrationId. This is in contrast to
 * [org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository] that uses
 * web session as a storage.
 *
 * If the cookie cannot be loaded and/or parsed it is as if there was nothing saved.
 */
class CookieServerOAuth2AuthorizedClientRepository(
    private val clientRegistrationRepository: ReactiveClientRegistrationRepository,
    private val cookieService: ReactiveCookieService
) : ServerOAuth2AuthorizedClientRepository {

    private val logger = KotlinLogging.logger {}

    override fun <T : OAuth2AuthorizedClient> loadAuthorizedClient(
        clientRegistrationId: String,
        principal: Authentication,
        exchange: ServerWebExchange
    ): Mono<T> {
        return Mono.just(exchange)
            .flatMap { serverWebExchange ->
                cookieService.decodeCookie<SimplifiedOAuth2AuthorizedClient>(
                    serverWebExchange,
                    SPRING_SEC_OAUTH2_AUTHZ_CLIENT,
                    mapper,
                )
            }
            .doOnNext { simplifiedAuthorizedClient ->
                // verify that loaded OAuth2AuthorizedClient uses provided clientRegistrationId
                val storedRegistrationId = simplifiedAuthorizedClient.registrationId
                if (storedRegistrationId != clientRegistrationId) {
                    throw IllegalStateException(
                        "Stored registrationId $storedRegistrationId " +
                            "does not correspond to expected $clientRegistrationId"
                    )
                }
                simplifiedAuthorizedClient.accessToken.expiresAt!! > Instant.now()!!
            }
            .flatMap { simplifiedAuthorizedClient ->
                simplifiedAuthorizedClient.toOAuth2AuthorizedClient(clientRegistrationRepository)
            }
            .map { authorizedClient ->
                @Suppress("UNCHECKED_CAST")
                authorizedClient as T
            }
    }

    override fun saveAuthorizedClient(
        authorizedClient: OAuth2AuthorizedClient,
        principal: Authentication,
        exchange: ServerWebExchange
    ): Mono<Void> {
        return Mono.just(exchange).flatMap { serverWebExchange ->
            cookieService.createCookie(
                serverWebExchange,
                SPRING_SEC_OAUTH2_AUTHZ_CLIENT,
                mapper.writeValueAsString(authorizedClient.toSimplified())
            )
        }.doOnSuccess {
            logger.debugToken(
                SPRING_SEC_OAUTH2_AUTHZ_CLIENT,
                "access_token",
                authorizedClient.accessToken.tokenValue
            )
            authorizedClient.refreshToken?.let { refreshToken ->
                logger.debugToken(
                    SPRING_SEC_OAUTH2_AUTHZ_CLIENT,
                    "refresh_token",
                    refreshToken.tokenValue
                )
            }
        }
    }

    override fun removeAuthorizedClient(
        clientRegistrationId: String?,
        principal: Authentication?,
        exchange: ServerWebExchange
    ): Mono<Void> {
        return Mono.just(exchange)
            .doOnNext { serverWebExchange ->
                cookieService.invalidateCookie(serverWebExchange, SPRING_SEC_OAUTH2_AUTHZ_CLIENT)
            }
            .then()
    }

    private fun SimplifiedOAuth2AuthorizedClient.toOAuth2AuthorizedClient(
        clientRegistrationRepository: ReactiveClientRegistrationRepository
    ): Mono<OAuth2AuthorizedClient> =
        clientRegistrationRepository
            .findByRegistrationId(registrationId)
            .map { clientRegistration ->
                OAuth2AuthorizedClient(clientRegistration, principalName, accessToken, refreshToken)
            }
}
