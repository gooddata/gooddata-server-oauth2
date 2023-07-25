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

import com.gooddata.oauth2.server.jackson.mapper
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

/**
 * Implementation of [ServerAuthorizationRequestRepository] that persists [OAuth2AuthorizationRequest] into
 * `SPRING_SEC_OAUTH2_AUTHZ_RQ` HTTP cookie. This is in contrast to default
 * [org.springframework.security.oauth2.client.web.server.WebSessionOAuth2ServerAuthorizationRequestRepository]
 * that uses server-side web session to store all authorization requests being processed.
 *
 * If the cookie cannot be loaded and/or parsed it is as if there was nothing saved.
 */
class CookieServerAuthorizationRequestRepository(
    private val cookieService: ReactiveCookieService
) : ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    override fun loadAuthorizationRequest(exchange: ServerWebExchange): Mono<OAuth2AuthorizationRequest> {
        return Mono.just(exchange)
            .flatMap { webExchange ->
                cookieService.decodeCookie<OAuth2AuthorizationRequest>(
                    webExchange,
                    SPRING_SEC_OAUTH2_AUTHZ_RQ,
                    mapper,
                )
            }
    }

    override fun saveAuthorizationRequest(
        authorizationRequest: OAuth2AuthorizationRequest,
        exchange: ServerWebExchange
    ): Mono<Void> {
        return Mono.just(exchange)
            .doOnNext { webExchange ->
                cookieService.createCookie(
                    webExchange,
                    SPRING_SEC_OAUTH2_AUTHZ_RQ,
                    mapper.writeValueAsString(authorizationRequest)
                )
            }
            .then()
    }

    override fun removeAuthorizationRequest(exchange: ServerWebExchange): Mono<OAuth2AuthorizationRequest> {
        return loadAuthorizationRequest(exchange)
            .doOnEach { cookieService.invalidateCookie(exchange, SPRING_SEC_OAUTH2_AUTHZ_RQ) }
    }
}
