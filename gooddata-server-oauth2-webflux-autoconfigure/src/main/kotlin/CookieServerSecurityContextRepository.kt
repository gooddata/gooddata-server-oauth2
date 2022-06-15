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

import com.gooddata.oauth2.server.common.SPRING_SEC_SECURITY_CONTEXT
import com.gooddata.oauth2.server.common.CookieDecodeException
import com.gooddata.oauth2.server.common.SPRING_SEC_OAUTH2_AUTHZ_CLIENT
import com.gooddata.oauth2.server.common.jackson.mapper
import com.gooddata.oauth2.server.common.logException
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
                    "id_token",
                    ((securityContext.authentication).principal as OidcUser).idToken.tokenValue
                )
            }
            .switchIfEmpty {
                Mono.fromRunnable { cookieService.invalidateCookie(exchange, SPRING_SEC_SECURITY_CONTEXT) }
            }
            .then()
    }

    override fun load(exchange: ServerWebExchange): Mono<SecurityContext> {
        return Mono.just(exchange)
            .flatMap { webExchange ->
                cookieService.decodeCookie<OAuth2AuthenticationToken>(
                    webExchange.request,
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
                                logger.logException(exception)
                                cookieService.invalidateCookie(exchange, SPRING_SEC_OAUTH2_AUTHZ_CLIENT)
                                cookieService.invalidateCookie(exchange, SPRING_SEC_SECURITY_CONTEXT)
                                CookieDecodeException("JWT from cookie decoding error", exception)
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
                            }
                    }
            }
            .map { oauthToken -> SecurityContextImpl(oauthToken) }
    }
}
