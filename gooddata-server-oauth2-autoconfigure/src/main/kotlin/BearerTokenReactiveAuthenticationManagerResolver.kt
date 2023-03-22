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
import com.nimbusds.jose.jwk.source.JWKSecurityContextJWKSet
import com.nimbusds.jose.proc.BadJOSEException
import com.nimbusds.jose.proc.BadJWSException
import com.nimbusds.jose.proc.JWKSecurityContext
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.proc.BadJWTException
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.reactor.mono
import mu.KotlinLogging
import org.springframework.security.authentication.AuthenticationServiceException
import org.springframework.security.authentication.DelegatingReactiveAuthenticationManager
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.jwt.JwtException
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder
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
                CustomJwtAuthenticationManager(organizationProvider),
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

//TODO naming
// TODO check JWSHeader.alg NONE, injected JWSHeader.jwk attacks
private class CustomJwtAuthenticationManager(
    private val organizationProvider: () -> Mono<Organization>,
) : ReactiveAuthenticationManager {

    private val logger = KotlinLogging.logger {}

    override fun authenticate(authentication: Authentication?) =
        Mono.justOrEmpty(authentication)
            .filter { authentication is BearerTokenAuthenticationToken }
            .cast(BearerTokenAuthenticationToken::class.java)
            .filter(::hasValidJwsHeader)
            .flatMap { jwtToken ->
                JwtReactiveAuthenticationManager(decoder())
                    .authenticate(jwtToken)
                    // TODO how to do it in a proper way??
                    //  ... we have same problem in the CookieServerSecurityContextRepository
                    .onErrorMap({ it.cause is JwtException }) { exception ->
                        when(val jwtCause = exception.cause?.cause) {
                            is BadJOSEException -> InvalidBearerTokenException(jwtCause.message, jwtCause)
                            else -> exception
                        }
                    }
            }

    // TODO optimize code
    private fun hasValidJwsHeader(authToken: BearerTokenAuthenticationToken): Boolean {
        return findRawJwsHeaderPart(authToken)
            ?.runCatching { JWSHeader.parse(Base64URL.from(this)) }
            ?.map(::representsJwtWithId)
            ?.getOrElse { exception ->
                // TODO not sure here, if we want to fail or consider as non-jwt
                logger.debug(exception) { "${authToken.token} is not a JWT token with a proper JOSE header." }
                // ignore parsing error - consider the token as non-JWT
                null
            } ?: false
    }

    private fun findRawJwsHeaderPart(authToken: BearerTokenAuthenticationToken) =
        authToken.token.trim().substringBefore('.', "").takeIf(String::isNotEmpty)

    // TODO decide keyID vs. "latest" JWK
    private fun representsJwtWithId(jwsHeader: JWSHeader): Boolean {
        return jwsHeader.keyID != null && jwsHeader.type == JOSEObjectType.JWT
    }

    // TODO same as in JwkCachingReactiveDecoderFactory
    private fun decoder() =
        NimbusReactiveJwtDecoder { signedJwt ->
            getJwkSet().map { jwkSet ->
                val jwtProcessor = DefaultJWTProcessor<JWKSecurityContext>()
                val securityContext = JWKSecurityContext(jwkSet.keys)
                jwtProcessor.jwsKeySelector = JWSVerificationKeySelector(
                    JWSAlgorithm.RS256,
                    JWKSecurityContextJWKSet()
                )
                jwtProcessor.jwtClaimsSetVerifier = JwkCachingReactiveDecoderFactory.ExpTimeCheckingJwtClaimsSetVerifier
                jwtProcessor.process(signedJwt, securityContext)
            }
        }

    // TODO can be abstract when extracted from JwkCachingFactory
    private fun getJwkSet(): Mono<JWKSet> = organizationProvider().map { organization ->
        organization.jwtAuthJwks?.let(::JWKSet) ?: TODO("proper error")
    }
}
