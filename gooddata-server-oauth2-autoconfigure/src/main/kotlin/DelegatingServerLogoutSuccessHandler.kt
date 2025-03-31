/*
 * (C) 2022 GoodData Corporation
 */
package com.gooddata.oauth2.server

import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono

/**
 * Delegates to a collection of {@link ServerLogoutSuccessHandler} implementations.
 */
class DelegatingServerLogoutSuccessHandler(
    vararg delegates: ServerLogoutSuccessHandler,
    private val client: AuthenticationStoreClient,
    private val auditClient: AuthenticationAuditClient,
) : ServerLogoutSuccessHandler {

    private val logger = KotlinLogging.logger {}
    private val delegates = delegates.toList()

    @Suppress("CyclomaticComplexMethod")
    override fun onLogoutSuccess(exchange: WebFilterExchange, authentication: Authentication): Mono<Void> {
        val sourceIp = exchange.exchange.request.remoteAddress?.address?.hostAddress
            ?: exchange.exchange.request.remoteAddress?.hostName

        return Flux.fromIterable(delegates).concatMap { delegate ->
            delegate.onLogoutSuccess(exchange, authentication)
        }.then(
            getOrganizationFromContext().flatMap { organization ->
                findAuthenticatedUser(client, organization, authentication)
                    .switchIfEmpty(Mono.just(User("<unauthorized user>")))
                    .flatMap { user ->
                        val authMethod = when (authentication) {
                            is OAuth2AuthenticationToken -> AuthMethod.OIDC
                            is JwtAuthenticationToken -> AuthMethod.JWT
                            is UserContextAuthenticationToken -> AuthMethod.API_TOKEN
                            else -> AuthMethod.NOT_APPLICABLE
                        }

                        val sessionContextIdentifier = when (authentication) {
                            is OAuth2AuthenticationToken -> authentication.getClaim(organization)
                            is JwtAuthenticationToken -> authentication.name
                            is UserContextAuthenticationToken -> authentication.user.usedTokenId
                            else -> null
                        }

                        auditClient.recordLogout(
                            orgId = organization.id,
                            userId = user.id,
                            source = sourceIp,
                            sessionContextType = authMethod,
                            sessionContextIdentifier = sessionContextIdentifier
                        )
                    }
            }
        )
    }
}
