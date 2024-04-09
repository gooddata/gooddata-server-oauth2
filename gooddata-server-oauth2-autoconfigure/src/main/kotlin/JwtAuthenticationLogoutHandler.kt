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

import org.springframework.http.HttpStatus
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.security.web.server.DefaultServerRedirectStrategy
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler
import org.springframework.web.server.ResponseStatusException
import reactor.core.publisher.Mono
import java.net.URI
import java.time.LocalDateTime
import java.time.ZoneOffset

/**
 * Realize logout if provider is Jwt
 *
 * @param client authentication client
 */
class JwtAuthenticationLogoutHandler(
    private val client: AuthenticationStoreClient,
) : ServerLogoutHandler, ServerLogoutSuccessHandler {

    private val redirectStrategy = DefaultServerRedirectStrategy()

    override fun logout(exchange: WebFilterExchange, authentication: Authentication?) =
        Mono.justOrEmpty(authentication)
            .filter { authentication is JwtAuthenticationToken }
            .cast(JwtAuthenticationToken::class.java)
            .flatMap { jwtToken ->
                getOrganizationFromContext().flatMap { organization ->
                    val jwtId = jwtToken.token.id
                    val jwtValidTo = LocalDateTime.ofInstant(jwtToken.token.expiresAt, ZoneOffset.UTC)
                    val tokenHash = hashStringWithMD5(jwtToken.token.tokenValue)
                    client.invalidateJwt(organization.id, jwtToken.name, tokenHash, jwtId, jwtValidTo)
                }.onErrorMap(::JwtAuthenticationLogoutException)
            }

    override fun onLogoutSuccess(exchange: WebFilterExchange, authentication: Authentication?): Mono<Void> =
        Mono.justOrEmpty(authentication)
            .filter { authentication is JwtAuthenticationToken }
            .flatMap {
                // TODO where should we redirect??
                redirectStrategy.sendRedirect(exchange.exchange, URI.create("/"))
            }
}

internal class JwtAuthenticationLogoutException(originalError: Throwable) : ResponseStatusException(
    HttpStatus.INTERNAL_SERVER_ERROR,
    "Could not logout JWT token. Reason: ${originalError.message}",
    originalError
)
