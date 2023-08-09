package com.gooddata.oauth2.server

import mu.KotlinLogging
import org.springframework.security.core.Authentication
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler
import reactor.core.publisher.Mono

class LoggingRedirectServerAuthenticationSuccessHandler(
    private val client: AuthenticationStoreClient,
) : RedirectServerAuthenticationSuccessHandler() {
    private val logger = KotlinLogging.logger { }

    override fun onAuthenticationSuccess(
        webFilterExchange: WebFilterExchange?,
        authentication: Authentication?,
    ): Mono<Void> {
        return super.onAuthenticationSuccess(webFilterExchange, authentication)
            .then(
                logAuthenticationWithOrgIdAndUserId(client, authentication, logger) {
                    withMessage { "User Authenticated" }
                    withAction("login")
                    withState("finished")
                }
            )
    }
}
