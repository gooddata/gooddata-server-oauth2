package com.gooddata.oauth2.server

import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.security.core.Authentication
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler
import org.springframework.security.web.server.savedrequest.ServerRequestCache
import reactor.core.publisher.Mono

class LoggingRedirectServerAuthenticationSuccessHandler(
    private val client: AuthenticationStoreClient,
    private val auditClient: AuthenticationAuditClient,
    cache: ServerRequestCache,
) : RedirectServerAuthenticationSuccessHandler() {

    init {
        setRequestCache(cache)
    }

    private val logger = KotlinLogging.logger { }

    override fun onAuthenticationSuccess(
        webFilterExchange: WebFilterExchange?,
        authentication: Authentication?,
    ): Mono<Void> {
        val sourceIp = webFilterExchange?.exchange?.request?.remoteAddress?.address?.hostAddress

        return super.onAuthenticationSuccess(webFilterExchange, authentication)
            .then(
                getOrganizationFromContext().flatMap { organization ->
                    findAuthenticatedUser(client, organization, authentication)
                        .switchIfEmpty(Mono.just(User("<unauthorized user>")))
                        .flatMap { user ->
                            auditClient.recordLoginSuccess(
                                orgId = organization.id,
                                userId = user.id,
                                source = sourceIp,
                                sessionContextType = AuthMethod.OIDC,
                                sessionContextIdentifier = authentication?.getClaim(organization) ?: ""
                            )
                        }
                }
            )
    }
}
