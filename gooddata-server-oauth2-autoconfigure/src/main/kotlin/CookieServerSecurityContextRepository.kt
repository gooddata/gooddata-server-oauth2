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
import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.oauth2.jwt.Jwt
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
    private val repositoryAwareOidcTokensRefreshingService: RepositoryAwareOidcTokensRefreshingService,
    private val authorizedClientRepository: ServerOAuth2AuthorizedClientRepository,
) : ServerSecurityContextRepository {

    private val logger = KotlinLogging.logger {}

    override fun save(exchange: ServerWebExchange, context: SecurityContext?): Mono<Void> {
        return Mono.justOrEmpty(context)
            // we support only OAuth2AuthenticationToken
            .filter { it.authentication is OAuth2AuthenticationToken }
            // we support only OidcUser
            .filter { it.authentication.principal is OidcUser }
            .switchIfEmpty {
                // when content == null or filters don't match
                logger.debug { "Delete security context" }
                deleteSecurityContextCookie(exchange)
                Mono.empty()
            }
            .flatMap { securityContext -> createSecurityContextCookie(exchange, securityContext.authentication) }
    }

    private fun createSecurityContextCookie(exchange: ServerWebExchange, authentication: Authentication): Mono<Void> {
        return cookieService.createCookie(
            exchange,
            SPRING_SEC_SECURITY_CONTEXT,
            mapper.writeValueAsString(authentication)
        ).doOnSuccess {
            logger.debugToken(
                SPRING_SEC_SECURITY_CONTEXT,
                "id_token",
                (authentication.principal as OidcUser).idToken.tokenValue
            )
        }
    }

    private fun deleteSecurityContextCookie(exchange: ServerWebExchange) {
        cookieService.invalidateCookie(exchange, SPRING_SEC_SECURITY_CONTEXT)
    }

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
                exchange,
                SPRING_SEC_SECURITY_CONTEXT,
                mapper,
            )
        }
        .flatMap { oauthToken -> oauthToken.decodeAndExpand(this) }
        .doOnNext { expandedToken ->
            // save token to cache
            attributes[OAUTH_TOKEN_CACHE_KEY] = expandedToken
        }
        .onErrorResume(CookieDecodeException::class.java) { exception ->
            logDecodingException(this, exception)
            Mono.just(this)
                .doOnNext(::deleteSecurityContextCookie)
                .flatMap { webExchange ->
                    authorizedClientRepository.removeAuthorizedClient(null, null, webExchange)
                }
                .then(Mono.error(exception))
        }

    private fun OAuth2AuthenticationToken.decodeAndExpand(
        exchange: ServerWebExchange,
    ): Mono<OAuth2AuthenticationToken> = clientRegistrationRepository
        // find registration based on its ID
        .findByRegistrationId(authorizedClientRegistrationId)
        .flatMap { registration ->
            jwtDecoderFactory.createDecoder(registration)
                // decode JWT token from JSON
                .decode((principal as OidcUser).idToken.tokenValue)
                .map { jwt -> createExpandedOAuth2Token(jwt, this, registration) }
                .sanitizeJwtException()
                .onErrorResume(InternalJwtExpiredException::class.java) { exception ->
                    tryToRefreshIdToken(this, registration, exchange)
                        // fallback to an original error
                        .switchIfEmpty(Mono.error(exception))
                }
                .onErrorMap({ it is JwtException || it is BadJWTException }) { exception ->
                    // translate to a cookie decoding exception
                    CookieDecodeException(
                        "Cannot read ID Token from the session: ${exception.message}.",
                        exception.cause,
                    )
                }
        }

    /**
     * Sanitizes JwtException. This will fix the empty reasoning when the non-JwtException error is chained
     * into the JwtException.
     */
    private fun <T> Mono<T>.sanitizeJwtException(): Mono<T> = onErrorMap(JwtException::class.java) { exception ->
        when (val exceptionCause = exception.cause) {
            is BadJWTException -> exceptionCause
            else -> exception
        }
    }

    private fun tryToRefreshIdToken(
        authToken: OAuth2AuthenticationToken,
        registration: ClientRegistration,
        exchange: ServerWebExchange,
    ) = repositoryAwareOidcTokensRefreshingService.refreshTokensIfPossible(registration, authToken, exchange)
        .flatMap { refreshedTokens ->
            val rawIdToken = refreshedTokens.additionalParameters[OidcParameterNames.ID_TOKEN]
            Mono.justOrEmpty(rawIdToken)
        }
        .flatMap { rawIdToken ->
            jwtDecoderFactory.createDecoder(registration).decode(rawIdToken.toString())
                .map { jwt -> createExpandedOAuth2Token(jwt, authToken, registration) }
                // save a new sec. context cookie
                .doOnNext { token -> createSecurityContextCookie(exchange, token) }
        }
        .sanitizeJwtException()

    private fun createExpandedOAuth2Token(
        idTokenJwt: Jwt,
        originalOAuth2Token: OAuth2AuthenticationToken,
        registration: ClientRegistration,
    ) = OAuth2AuthenticationToken(
        DefaultOidcUser(
            originalOAuth2Token.principal.authorities,
            OidcIdToken(idTokenJwt.tokenValue, idTokenJwt.issuedAt, idTokenJwt.expiresAt, idTokenJwt.claims),
            registration.providerDetails.userInfoEndpoint.userNameAttributeName
        ),
        emptyList(), // it is not stored in JSON anyway
        registration.registrationId
    )

    /**
     * Logs token decoding [Exception] based on the level. If the level is:
     * * `DEBUG` - the exception message along with the full stacktrace is logged
     * * other - only the exception message is logged
     *
     * @receiver the Kotlin logger
     * @param[exception] token decoding [Exception] which should be logged
     */
    private fun logDecodingException(exchange: ServerWebExchange, exception: Exception) {
        val organizationId = exchange.maybeOrganizationFromAttributes()?.id
        val message = "Stored JWT token cannot be decoded: ${exception.message}, cause: ${exception.cause?.message}"
        when (logger.isDebugEnabled()) {
            true -> logger.logDebug {
                withOrganizationId(organizationId)
                withException(exception)
                withMessage { message }
            }
            false -> logger.logInfo {
                withOrganizationId(organizationId)
                withMessage { message }
            }
        }
    }

    companion object {
        internal const val OAUTH_TOKEN_CACHE_KEY = "oauthTokenFromCookieCache"
    }
}
