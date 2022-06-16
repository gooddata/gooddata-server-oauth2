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
package com.gooddata.oauth2.server.reactive

import com.gooddata.oauth2.server.common.SPRING_SEC_OAUTH2_AUTHZ_CLIENT
import com.gooddata.oauth2.server.common.jackson.SimplifiedOAuth2AuthorizedClient
import com.gooddata.oauth2.server.common.jackson.mapper
import com.gooddata.oauth2.server.common.jackson.toSimplified
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
            .flatMap {
                cookieService.decodeCookie<SimplifiedOAuth2AuthorizedClient>(
                    it.request,
                    SPRING_SEC_OAUTH2_AUTHZ_CLIENT,
                    mapper,
                )
            }
            .doOnNext {
                // verify that loaded OAuth2AuthorizedClient uses provided clientRegistrationId
                val stored = it.registrationId
                if (stored != clientRegistrationId) {
                    throw IllegalStateException(
                        "Stored registrationId $stored does not correspond to expected $clientRegistrationId"
                    )
                }
            }
            .flatMap { it.toOAuth2AuthorizedClient(clientRegistrationRepository) }
            .map {
                @Suppress("UNCHECKED_CAST")
                it as T
            }
    }

    override fun saveAuthorizedClient(
        authorizedClient: OAuth2AuthorizedClient,
        principal: Authentication,
        exchange: ServerWebExchange
    ): Mono<Void> {
        return Mono.just(exchange)
            .doOnNext { serverWebExchange ->
                cookieService.createCookie(
                    serverWebExchange,
                    SPRING_SEC_OAUTH2_AUTHZ_CLIENT,
                    mapper.writeValueAsString(authorizedClient.toSimplified())
                )
                logger.debugToken(
                    SPRING_SEC_OAUTH2_AUTHZ_CLIENT,
                    "access_token",
                    authorizedClient.accessToken.tokenValue
                )
            }
            .then()
    }

    override fun removeAuthorizedClient(
        clientRegistrationId: String,
        principal: Authentication?,
        exchange: ServerWebExchange
    ): Mono<Void> {
        return Mono.just(exchange)
            .doOnNext { cookieService.invalidateCookie(it, SPRING_SEC_OAUTH2_AUTHZ_CLIENT) }
            .then()
    }

    private fun SimplifiedOAuth2AuthorizedClient.toOAuth2AuthorizedClient(
        clientRegistrationRepository: ReactiveClientRegistrationRepository
    ): Mono<OAuth2AuthorizedClient> =
        clientRegistrationRepository.findByRegistrationId(registrationId)
            .map { OAuth2AuthorizedClient(it, principalName, accessToken, refreshToken) }
}
