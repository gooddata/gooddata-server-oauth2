/*
 * (C) 2023 GoodData Corporation
 */

package com.gooddata.oauth2.server

import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.web.server.DefaultServerRedirectStrategy
import org.springframework.security.web.server.ServerRedirectStrategy
import org.springframework.security.web.server.savedrequest.ServerRequestCache
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.util.UriComponentsBuilder
import reactor.core.publisher.Mono

internal object SilentAuthenticationUtils {
    private const val SILENT_AUTH_ENABLED_ATTRIBUTE_NAME = "oauth2SilentAuthEnabled"

    fun ServerWebExchange.hasSilentAuthEnabled() = attributes[SILENT_AUTH_ENABLED_ATTRIBUTE_NAME] == true

    fun ServerWebExchange.setSilentAuthEnabled() {
        attributes[SILENT_AUTH_ENABLED_ATTRIBUTE_NAME] = true
    }
}

class SilentAuthenticationRequestRedirectProvider(
    private val authorizationRequestResolver: ServerOAuth2AuthorizationRequestResolver,
    private val authorizationRequestRepository: ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest>,
    private val serverRequestCache: ServerRequestCache,
    private val authorizationRedirectStrategy: ServerRedirectStrategy = DefaultServerRedirectStrategy(),
) {
    @Deprecated("kra")
    fun sendRedirect(exchange: ServerWebExchange, registrationId: String, idTokenHint: String): Mono<Void> =
        authorizationRequestResolver.resolve(exchange, registrationId)
            .flatMap { authRequest ->
                val silentAuthRequest = authRequest.convertToSilentAuthRequest(idTokenHint)
                sendRedirectForAuthorization(exchange, silentAuthRequest)
            }

    private fun OAuth2AuthorizationRequest.convertToSilentAuthRequest(idTokenHint: String) =
        OAuth2AuthorizationRequest.from(this).parameters { attributes ->
            attributes.putAll(SilentAuthParameters.forIdTokenHint(idTokenHint))
        }.build()

    private fun sendRedirectForAuthorization(
        exchange: ServerWebExchange,
        authorizationRequest: OAuth2AuthorizationRequest,
    ): Mono<Void> = Mono.defer {
        val redirectUri = UriComponentsBuilder.fromUriString(authorizationRequest.authorizationRequestUri)
            .build(true)
            .toUri()

        authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, exchange)
            .then(serverRequestCache.saveRequest(exchange))
            .then(this.authorizationRedirectStrategy.sendRedirect(exchange, redirectUri))
    }

    private object SilentAuthParameters {
        private val PROMPT_NONE_ATTRIBUTE = "prompt" to "none"
        private const val TOKEN_HINT_ATTRIBUTE_KEY = "id_token_hint"

        fun forIdTokenHint(tokenHint: String): Map<String, String> = mapOf(
            PROMPT_NONE_ATTRIBUTE,
            TOKEN_HINT_ATTRIBUTE_KEY to tokenHint
        )
    }
}


