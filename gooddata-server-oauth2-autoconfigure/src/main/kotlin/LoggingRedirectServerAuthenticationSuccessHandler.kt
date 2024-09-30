package com.gooddata.oauth2.server

import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.security.core.Authentication
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler
import org.springframework.security.web.server.savedrequest.ServerRequestCache
import reactor.core.publisher.Mono

class LoggingRedirectServerAuthenticationSuccessHandler(
    private val client: AuthenticationStoreClient,
    cache: ServerRequestCache
) : RedirectServerAuthenticationSuccessHandler() {

    init {
        setRequestCache(cache)
    }

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
                    withAuthenticationMethod("OIDC")
                }
            )
    }
}
