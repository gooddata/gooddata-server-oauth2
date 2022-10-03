/*
 * (C) 2022 GoodData Corporation
 */
package com.gooddata.oauth2.server

import org.springframework.security.core.Authentication
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono

/**
 * Delegates to a collection of {@link ServerLogoutSuccessHandler} implementations.
 */
class DelegatingServerLogoutSuccessHandler(
    vararg delegates: ServerLogoutSuccessHandler
) : ServerLogoutSuccessHandler {

    private val delegates = delegates.toList()

    override fun onLogoutSuccess(exchange: WebFilterExchange, authentication: Authentication): Mono<Void> =
        Flux.fromIterable(delegates).concatMap { delegate ->
            delegate.onLogoutSuccess(exchange, authentication)
        }.then()
}
