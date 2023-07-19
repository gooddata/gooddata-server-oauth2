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

import com.gooddata.oauth2.server.JwtVerificationException.Companion.invalidClaimsMessage
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.reactor.mono
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtException
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.text.ParseException

/**
 * [ReactiveAuthenticationManagerResolver] that is able to authenticate bearer tokens.
 */
class BearerTokenReactiveAuthenticationManagerResolver(
    private val client: AuthenticationStoreClient,
) : ReactiveAuthenticationManagerResolver<ServerWebExchange> {

    override fun resolve(exchange: ServerWebExchange): Mono<ReactiveAuthenticationManager> =
        Mono.just(exchange).map { webExchange ->
            val organizationProvider = {
                mono { client.getOrganizationByHostname(webExchange.request.uri.host) }
            }
            CustomDelegatingReactiveAuthenticationManager(
                JwtAuthenticationManager(client, organizationProvider),
                PersistentApiTokenAuthenticationManager(client, organizationProvider)
            )
        }
}

/**
 * [ReactiveAuthenticationManager] that is responsible for handling API token authentication
 */
private class PersistentApiTokenAuthenticationManager(
    private val client: AuthenticationStoreClient,
    private val organizationProvider: () -> Mono<Organization>,
) : ReactiveAuthenticationManager {

    override fun authenticate(authentication: Authentication?): Mono<Authentication> =
        Mono.justOrEmpty(authentication)
            .filter { authentication is BearerTokenAuthenticationToken }
            .cast(BearerTokenAuthenticationToken::class.java)
            .flatMap { authToken ->
                organizationProvider().flatMap { organization ->
                    mono(Dispatchers.Unconfined) { client.getUserByApiToken(organization.id, authToken.token) }
                        .map { user -> UserContextAuthenticationToken(organization, user) }
                }
            }
}

/**
 * [ReactiveAuthenticationManager] that is responsible for handling JWT authentications
 */
private class JwtAuthenticationManager(
    private val client: AuthenticationStoreClient,
    private val organizationProvider: () -> Mono<Organization>,
    private val jwtTokenValidator: OAuth2TokenValidator<Jwt> = CustomOAuth2Validator(),
) : ReactiveAuthenticationManager {

    override fun authenticate(authentication: Authentication?): Mono<Authentication> {
        return Mono.justOrEmpty(authentication)
            .filter { authentication is BearerTokenAuthenticationToken }
            .cast(BearerTokenAuthenticationToken::class.java)
            .filter(::isJwtBearerToken)
            .flatMap { jwtToken ->
                val decoder = prepareJwtDecoder(
                    getJwkSet(),
                    supportedJwsAlgorithms
                )
                decoder.setJwtValidator(jwtTokenValidator)
                JwtReactiveAuthenticationManager(decoder).authenticate(jwtToken)
                    .onErrorMap({ it.cause is JwtException }) { ex -> parseJwtException(ex, jwtToken) }
            }
    }

    private fun parseJwtException(ex: Throwable, jwtToken: BearerTokenAuthenticationToken) = when (ex.cause?.cause) {
        is ParseException -> JwtDecodeException()
        is InternalJwtExpiredException -> JwtExpiredException()
        else -> JwtVerificationException(invalidClaimsMessage(jwtToken.missingMandatoryClaims()))
    }

    private fun isJwtBearerToken(authToken: BearerTokenAuthenticationToken) =
        jwtBearerTokenRegex.matches(authToken.token.trim())

    private fun getJwkSet(): Mono<JWKSet> = organizationProvider().flatMap { organization ->
        mono {
            client.getJwks(organization.id).let(::JWKSet)
        }
    }

    companion object {
        private const val BASE_64_REGEX = "[A-Za-z0-9+/_-]+={0,2}"
        private val jwtBearerTokenRegex = Regex("^$BASE_64_REGEX\\.$BASE_64_REGEX\\.$BASE_64_REGEX")
        private val supportedJwsAlgorithms = setOf(JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512)
        private val mandatoryClaims = listOf("name", "sub", "iat", "exp")

        private fun BearerTokenAuthenticationToken.missingMandatoryClaims(): List<String> = try {
            val tokenClaims = SignedJWT.parse(token).jwtClaimsSet.claims.keys
            mandatoryClaims.minus(tokenClaims)
        } catch (ex: ParseException) {
            emptyList()
        }
    }
}
