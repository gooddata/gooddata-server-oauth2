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
import com.nimbusds.jwt.proc.BadJWTException
import mu.KotlinLogging
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.oauth2.jwt.JwtException
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoderFactory
import org.springframework.security.web.server.context.ServerSecurityContextRepository
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import reactor.kotlin.core.publisher.switchIfEmpty

/**
 * [ServerSecurityContextRepository] implementation that stores [SecurityContext] information into
 * `SPRING_SEC_SECURITY_CONTEXT` HTTP cookie. Security context is not stored as a whole but only JWT part of OAuth2
 * ID token together with some additional necessary information. This is in contrast to default
 * [org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository] that uses web sessions.
 *
 * To avoid redundant decoding of the cookie, when the resulting [Mono] produced from the [load] function is subscribed
 * multiple times, the [OAuth2AuthenticationToken] decoded from the cookie is cached for a single API request.
 * This saves the time of expensive cookie decryption and also saves a possible I/O for [CookieSecurityProperties].
 * The caching mechanism is implemented by simple saving the token value within the [ServerWebExchange] attributes.
 */
class CookieServerSecurityContextRepository(
    private val clientRegistrationRepository: ReactiveClientRegistrationRepository,
    private val cookieService: ReactiveCookieService,
    private val jwtDecoderFactory: ReactiveJwtDecoderFactory<ClientRegistration>,
) : ServerSecurityContextRepository {

    private val logger = KotlinLogging.logger {}

    override fun save(exchange: ServerWebExchange, context: SecurityContext?): Mono<Void> {
        return Mono.justOrEmpty(context)
            // we support only OAuth2AuthenticationToken
            .filter { it.authentication is OAuth2AuthenticationToken }
            // we support only OidcUser
            .filter { it.authentication.principal is OidcUser }
            .map { securityContext ->
                cookieService.createCookie(
                    exchange,
                    SPRING_SEC_SECURITY_CONTEXT,
                    mapper.writeValueAsString(securityContext.authentication)
                )
                logger.debugToken(
                    SPRING_SEC_SECURITY_CONTEXT,
                    "id_token",
                    (securityContext.authentication.principal as OidcUser).idToken.tokenValue
                )
            }
            .switchIfEmpty {
                // when content == null or filters don't match
                logger.debug { "Delete security context" }
                Mono.just(deleteSecurityContext(exchange))
            }
            .then()
    }

    private fun deleteSecurityContext(exchange: ServerWebExchange) =
        cookieService.invalidateCookie(exchange, SPRING_SEC_SECURITY_CONTEXT)

    override fun load(exchange: ServerWebExchange): Mono<SecurityContext> =
        Mono.just(exchange)
            .flatMap { webExchange ->
                // This cannot be a top-level Mono (therefore the `Mono.just(exchange)`)
                // because we always need emit this each time the new subscription is processed.
                Mono.justOrEmpty(webExchange.attributes[OAUTH_TOKEN_CACHE_KEY])
                    .filter { cacheValue -> cacheValue is OAuth2AuthenticationToken }
                    .map { tokenCacheValue -> tokenCacheValue as OAuth2AuthenticationToken }
                    .switchIfEmpty(webExchange.loadTokenFromCookie())
            }
            .map(::SecurityContextImpl)

    private fun ServerWebExchange.loadTokenFromCookie() = Mono.just(this)
        .flatMap { exchange ->
            cookieService.decodeCookie<OAuth2AuthenticationToken>(
                exchange.request,
                SPRING_SEC_SECURITY_CONTEXT,
                mapper,
            )
        }
        .flatMap { oauthToken ->
            // find registration based on its ID
            clientRegistrationRepository.findByRegistrationId(oauthToken.authorizedClientRegistrationId)
                .flatMap { registration ->
                    jwtDecoderFactory.createDecoder(registration)
                        // decode JWT token from JSON
                        .decode((oauthToken.principal as OidcUser).idToken.tokenValue)
                        .onErrorMap(JwtException::class.java) { exception ->
                            // Sanitizes JwtException. This will get fix the empty reasoning
                            // when the non-JwtException error is chained into the JwtException
                            val sanitizedException = when (val cause = exception.cause) {
                                is BadJWTException -> cause
                                else -> exception
                            }
                            logDecodingException(sanitizedException)
                            cookieService.invalidateCookie(this, SPRING_SEC_OAUTH2_AUTHZ_CLIENT)
                            cookieService.invalidateCookie(this, SPRING_SEC_SECURITY_CONTEXT)
                            CookieDecodeException(
                                "Cannot read ID Token from the session: ${sanitizedException.message}.",
                                cause = sanitizedException.cause,
                            )
                        }
                        .map { jwt -> OidcIdToken(jwt.tokenValue, jwt.issuedAt, jwt.expiresAt, jwt.claims) }
                        .map { oidcToken ->
                            OAuth2AuthenticationToken(
                                DefaultOidcUser(
                                    oauthToken.principal.authorities,
                                    oidcToken,
                                    registration.providerDetails.userInfoEndpoint.userNameAttributeName
                                ),
                                emptyList(), // it is not stored in JSON anyway
                                registration.registrationId
                            )
                        }.doOnNext { tokenFromCookie ->
                            // save token to cache
                            attributes[OAUTH_TOKEN_CACHE_KEY] = tokenFromCookie
                        }
                }
        }

    /**
     * Logs token decoding [Exception] based on the level. If the level is:
     * * `DEBUG` - the exception message along with the full stacktrace is logged
     * * other - only the exception message is logged
     *
     * @receiver the Kotlin logger
     * @param[exception] token decoding [Exception] which should be logged
     */
    private fun logDecodingException(exception: Exception) {
        val message = "Stored JWT token cannot be decoded: ${exception.message}, cause: ${exception.cause?.message}"
        when (logger.isDebugEnabled) {
            true -> logger.debug(exception) { message }
            false -> logger.info { message }
        }
    }

    companion object {
        internal const val OAUTH_TOKEN_CACHE_KEY = "oauthTokenFromCookieCache"
    }
}
