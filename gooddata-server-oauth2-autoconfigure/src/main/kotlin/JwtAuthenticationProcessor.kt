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

import com.nimbusds.jwt.JWTClaimNames
import java.time.Instant
import kotlinx.coroutines.reactor.mono
import mu.KotlinLogging
import org.springframework.http.HttpStatus
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler
import org.springframework.web.server.ResponseStatusException
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono

/**
 * If `SecurityContext` contains [JwtAuthenticationToken] the [JwtAuthenticationProcessor] handles the
 * authentication by retrieving [Organization] by request uri host, and authenticating the user based on `Jwks`
 * configured for the given organization.
 */
class JwtAuthenticationProcessor(
    private val client: AuthenticationStoreClient,
    private val serverLogoutHandler: ServerLogoutHandler,
    private val reactorUserContextProvider: ReactorUserContextProvider
) : AuthenticationProcessor<JwtAuthenticationToken>(reactorUserContextProvider) {

    private val logger = KotlinLogging.logger {}

    // TODO optimize organization get (performance can be improved because org is requested also during JWT decoding)
    override fun authenticate(
        authenticationToken: JwtAuthenticationToken,
        exchange: ServerWebExchange,
        chain: WebFilterChain,
    ): Mono<Void> = mono { client.getOrganizationByHostname(exchange.request.uri.host) }
        .flatMap { organization -> validateJwtToken(exchange, authenticationToken, organization) }
        .flatMap { organization ->
            getUserForJwtToken(exchange, chain, authenticationToken, organization).flatMap { user ->
                val userName = authenticationToken.tokenAttributes["name"].toString()
                withUserContext(organization, user, userName) {
                    chain.filter(exchange)
                }
            }
        }

    private fun validateJwtToken(
        exchange: ServerWebExchange,
        token: JwtAuthenticationToken,
        organization: Organization
    ): Mono<Organization> {
        val tokenHash = getMd5TokenHashFromAuthenticationHeader(exchange)
        val jwtId = token.tokenAttributes[JWTClaimNames.JWT_ID]?.toString() ?: throw JwtVerificationException()
        return mono { client.isValidJwt(organization.id, token.name, tokenHash, jwtId) }.map { isValid ->
            when (isValid) {
                true -> organization
                false -> throw JwtDisabledException()
            }
        }
    }

    private fun getUserForJwtToken(
        exchange: ServerWebExchange,
        chain: WebFilterChain,
        authenticationToken: JwtAuthenticationToken,
        organization: Organization,
    ): Mono<User> {
        logger.info { "getUserForJwtToken ${authenticationToken.name} ${organization.id}" }
        return mono {
            client.getUserById(organization.id, authenticationToken.name) ?: throw ResponseStatusException(
                HttpStatus.NOT_FOUND,
                "User with ID='${authenticationToken.name}' is not registered"
            )
        }.flatMap { user ->
            val tokenIssuedAtTime = authenticationToken.tokenAttributes[JWTClaimNames.ISSUED_AT] as Instant
            val lastLogoutAllTimestamp = user.lastLogoutAllTimestamp
            val isValid = lastLogoutAllTimestamp == null || tokenIssuedAtTime.isAfter(lastLogoutAllTimestamp)
            logger.info { "getUserForJwtToken is valid $tokenIssuedAtTime $lastLogoutAllTimestamp $isValid" }
            if (!isValid) {
                serverLogoutHandler.logout(WebFilterExchange(exchange, chain), authenticationToken)
                    .then(Mono.error(JwtDisabledException()))
            } else Mono.just(user)
        }
    }
}
