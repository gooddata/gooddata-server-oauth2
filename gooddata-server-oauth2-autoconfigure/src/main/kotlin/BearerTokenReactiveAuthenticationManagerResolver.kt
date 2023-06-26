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

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.proc.BadJOSEException
import com.nimbusds.jose.util.Base64URL
import java.text.ParseException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.reactor.mono
import org.springframework.security.authentication.DelegatingReactiveAuthenticationManager
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.jwt.JwtException
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

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
            DelegatingReactiveAuthenticationManager(
                JwtAuthenticationManager(client, organizationProvider),
                PersistentApiTokenAuthenticationManager(client, organizationProvider)
            )
        }
}

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

internal class JwtAuthenticationManager(
    private val client: AuthenticationStoreClient,
    private val organizationProvider: () -> Mono<Organization>,
) : ReactiveAuthenticationManager {

    override fun authenticate(authentication: Authentication?): Mono<Authentication> {
        return Mono.justOrEmpty(authentication)
            .filter { authentication is BearerTokenAuthenticationToken }
            .cast(BearerTokenAuthenticationToken::class.java)
            .filter(::hasValidJwsHeader)
            .flatMap { jwtToken ->
                val decoder = prepareJwtDecoder(
                    getJwkSet(),
                    setOf(JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512)
                )
                decoder.setJwtValidator(CustomOAuth2Validator())
                JwtReactiveAuthenticationManager(decoder).authenticate(jwtToken)
                    // TODO can we handle this better? Same as in the CookieServerSecurityContextRepository
                    .onErrorMap({ it.cause is JwtException }) { exception ->
                        when (val jwtCause = exception.cause?.cause) {
                            is BadJOSEException -> InvalidBearerTokenException(jwtCause.message, jwtCause)
                            else -> exception
                        }
                    }
            }
    }

    private fun hasValidJwsHeader(authToken: BearerTokenAuthenticationToken): Boolean {
        val rawHeader = findRawJwsHeaderPart(authToken)
        return if (rawHeader != null) {
            validateJwtHeader(rawHeader)
            true
        } else {
            false
        }
    }

    private fun findRawJwsHeaderPart(authToken: BearerTokenAuthenticationToken) =
        authToken.token.trim().substringBefore('.', "").takeIf(String::isNotEmpty)

    private fun validateJwtHeader(url: String) {
        val result = try {
            JWSHeader.parse(Base64URL.from(url))
        } catch (exception: ParseException) {
            throw InvalidBearerTokenException("Token contains invalid JOSE header.", exception)
        }
        if (!representJwtWithId(result)) {
            throw InvalidBearerTokenException("Invalid jws header. Header must be of JWT type and with non-null keyId.")
        }
    }

    private fun representJwtWithId(jwsHeader: JWSHeader) =
        jwsHeader.keyID != null && jwsHeader.type == JOSEObjectType.JWT

    private fun getJwkSet(): Mono<JWKSet> = organizationProvider().flatMap { organization ->
        mono {
            client.getJwks(organization.id).let(::JWKSet)
        }
    }
}
