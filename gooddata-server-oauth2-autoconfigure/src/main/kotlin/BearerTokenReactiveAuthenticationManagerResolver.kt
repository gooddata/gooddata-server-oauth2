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
import com.nimbusds.jose.proc.BadJWSException
import com.nimbusds.jwt.SignedJWT
import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtClaimNames
import org.springframework.security.oauth2.jwt.JwtException
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.text.ParseException

/**
 * [ReactiveAuthenticationManagerResolver] that is able to authenticate bearer tokens.
 */
class BearerTokenReactiveAuthenticationManagerResolver(
    private val client: AuthenticationStoreClient,
    private val auditClient: AuthenticationAuditClient,
) : ReactiveAuthenticationManagerResolver<ServerWebExchange> {
    override fun resolve(exchange: ServerWebExchange): Mono<ReactiveAuthenticationManager> =
        Mono.just(exchange).map {
            val sourceIp = exchange.request.remoteAddress?.address?.hostAddress

            CustomDelegatingReactiveAuthenticationManager(
                JwtAuthenticationManager(client, auditClient, sourceIp),
                PersistentApiTokenAuthenticationManager(client, auditClient, sourceIp)
            )
        }
}

/**
 * [ReactiveAuthenticationManager] that is responsible for handling API token authentication
 */
private class PersistentApiTokenAuthenticationManager(
    private val client: AuthenticationStoreClient,
    private val auditClient: AuthenticationAuditClient,
    private val sourceIp: String?,
) : ReactiveAuthenticationManager {
    private val logger = KotlinLogging.logger { }

    override fun authenticate(authentication: Authentication?): Mono<Authentication> =
        Mono.justOrEmpty(authentication)
            .filter { authentication is BearerTokenAuthenticationToken }
            .cast(BearerTokenAuthenticationToken::class.java)
            .flatMap { authToken ->
                getOrganizationFromContext().flatMap { organization ->
                    client.getUserByApiToken(organization.id, authToken.token).flatMap { user ->
                        val token = UserContextAuthenticationToken(organization, user)
                        auditClient.recordLoginSuccess(
                            orgId = organization.id,
                            userId = user.id,
                            source = sourceIp,
                            sessionContextType = AuthMethod.API_TOKEN,
                            sessionContextIdentifier = user.usedTokenId
                        ).thenReturn(token)
                    }.onErrorResume { ex ->
                        auditClient.recordLoginFailure(
                            orgId = organization.id,
                            userId = "", // User ID is not available during failed authentication
                            source = sourceIp,
                            sessionContextType = AuthMethod.API_TOKEN,
                            sessionContextIdentifier = "",
                            errorCode = "INVALID_BEARER_TOKEN",
                        ).then(Mono.error(ex))
                    }
                }
            }
}

/**
 * [ReactiveAuthenticationManager] that is responsible for handling JWT authentications
 */
private class JwtAuthenticationManager(
    private val client: AuthenticationStoreClient,
    private val auditClient: AuthenticationAuditClient,
    private val sourceIp: String?,
    private val jwtTokenValidator: OAuth2TokenValidator<Jwt> = CustomOAuth2Validator(),
) : ReactiveAuthenticationManager {

    private val logger = KotlinLogging.logger {}

    override fun authenticate(authentication: Authentication?): Mono<Authentication> {
        return Mono.justOrEmpty(authentication)
            .filter { authentication is BearerTokenAuthenticationToken }
            .cast(BearerTokenAuthenticationToken::class.java)
            .filter(::isJwtBearerToken)
            .flatMap(::authenticate)
    }

    private fun authenticate(jwtToken: BearerTokenAuthenticationToken): Mono<Authentication> {
        return getOrganizationFromContext().flatMap { organization ->
            val decoder = prepareJwtDecoder(getJwkSet(organization.id), supportedJwsAlgorithms)
                .apply { setJwtValidator(jwtTokenValidator) }
            JwtReactiveAuthenticationManager(decoder).authenticate(jwtToken)
                .onErrorResume({ it.cause is JwtException }) { ex ->
                    logger.logError(ex) {
                        withAction("login")
                        withMessage { "authentication failed: ${ex.message}" }
                        withState("error")
                        withAuthenticationMethod(AUTH_METHOD)
                    }
                    recordAuditForJwtAuthenticationError(organization.id, ex, jwtToken)
                }
                .doOnNext { token ->
                    logFinishedJwtAuthentication(organization.id, token)
                }
        }
    }

    @Suppress("LongMethod", "CyclomaticComplexMethod", "NestedBlockDepth")
    private fun recordAuditForJwtAuthenticationError(
        orgId: String,
        ex: Throwable,
        jwtToken: BearerTokenAuthenticationToken
    ): Mono<Authentication> {
        return when (ex.cause?.cause) {
            is ParseException -> {
                auditClient.recordLoginFailure(
                    orgId = orgId,
                    userId = "",
                    source = sourceIp,
                    sessionContextType = AuthMethod.JWT,
                    sessionContextIdentifier = "",
                    errorCode = "JWT_DECODE_ERROR",
                    details = mapOf("errorMessage" to "JWT token could not be parsed")
                ).then(
                    Mono.error(JwtDecodeException())
                )
            }
            else -> {
                try {
                    val jwt = SignedJWT.parse(jwtToken.token)
                    val subClaim = jwt.jwtClaimsSet.getStringClaim(JwtClaimNames.SUB)
                    val details = mutableMapOf<String, Any>()

                    listOf(
                        JwtClaimNames.ISS,
                        JwtClaimNames.AUD,
                        JwtClaimNames.EXP,
                        JwtClaimNames.JTI,
                        JwtClaimNames.IAT,
                        JwtClaimNames.NBF
                    ).forEach { claimName ->
                        jwt.jwtClaimsSet.getClaim(claimName)?.let {
                            details[claimName] = it.toString()
                        }
                    }

                    val errorMessage = when (ex.cause?.cause) {
                        is InternalJwtExpiredException -> "JWT token has expired"
                        is BadJWSException -> "JWT signature verification failed"
                        else -> invalidClaimsMessage(jwtToken.missingMandatoryClaims())
                    }
                    details["errorMessage"] = errorMessage

                    auditClient.recordLoginFailure(
                        orgId = orgId,
                        userId = subClaim ?: "",
                        source = sourceIp,
                        sessionContextType = AuthMethod.JWT,
                        sessionContextIdentifier = subClaim ?: "",
                        errorCode = when (ex.cause?.cause) {
                            is InternalJwtExpiredException -> "JWT_EXPIRED"
                            is BadJWSException -> "JWT_SIGNATURE_ERROR"
                            else -> "JWT_VERIFICATION_ERROR"
                        },
                        details = details
                    ).then(
                        Mono.error(parseJwtException(ex, jwtToken))
                    )
                } catch (_: ParseException) {
                    auditClient.recordLoginFailure(
                        orgId = orgId,
                        userId = "",
                        source = sourceIp,
                        sessionContextType = AuthMethod.JWT,
                        sessionContextIdentifier = "",
                        errorCode = "JWT_DECODE_ERROR",
                        details = mapOf("errorMessage" to "JWT token could not be parsed")
                    ).then(
                        Mono.error(parseJwtException(ex, jwtToken))
                    )
                }
            }
        }
    }

    private fun parseJwtException(ex: Throwable, jwtToken: BearerTokenAuthenticationToken) = when (ex.cause?.cause) {
        is ParseException -> JwtDecodeException()
        is InternalJwtExpiredException -> JwtExpiredException()
        is BadJWSException -> JwtSignatureException()
        else -> JwtVerificationException(invalidClaimsMessage(jwtToken.missingMandatoryClaims()))
    }

    private fun isJwtBearerToken(authToken: BearerTokenAuthenticationToken) =
        jwtBearerTokenRegex.matches(authToken.token.trim())

    private fun getJwkSet(organizationId: String): Mono<JWKSet> = client.getJwks(organizationId).map(::JWKSet)

    private fun logFinishedJwtAuthentication(organizationId: String, token: Authentication) {
        if (token is JwtAuthenticationToken) {
            client.getUserById(organizationId, token.name).map { user ->
                auditClient.recordLoginSuccess(
                    orgId = organizationId,
                    userId = user.id,
                    source = sourceIp,
                    sessionContextType = AuthMethod.JWT,
                    sessionContextIdentifier = token.name
                )
            }
        }
    }

    companion object {
        private const val BASE_64_REGEX = "[A-Za-z0-9+/_-]+={0,2}"
        private const val AUTH_METHOD = "JWT"
        private val jwtBearerTokenRegex = Regex("^$BASE_64_REGEX\\.$BASE_64_REGEX\\.$BASE_64_REGEX")
        private val supportedJwsAlgorithms = setOf(JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512)
        private val mandatoryClaims = listOf("name", "sub", "iat", "exp")

        private fun BearerTokenAuthenticationToken.missingMandatoryClaims(): List<String> = try {
            val tokenClaims = SignedJWT.parse(token).jwtClaimsSet.claims.keys
            mandatoryClaims.minus(tokenClaims)
        } catch (_: ParseException) {
            emptyList()
        }
    }
}
