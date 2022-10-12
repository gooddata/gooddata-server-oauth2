/*
 * (C) 2022 GoodData Corporation
 */
package com.gooddata.oauth2.server

import org.springframework.security.core.Authentication
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler
import org.springframework.security.web.server.context.ServerSecurityContextRepository
import reactor.core.publisher.Mono

class SecurityContextRepositoryLogoutHandler(
    private val serverSecurityContextRepository: ServerSecurityContextRepository
) : ServerLogoutHandler {

    override fun logout(exchange: WebFilterExchange, authentication: Authentication): Mono<Void> =
        deleteSecurityContext(exchange)

    private fun deleteSecurityContext(exchange: WebFilterExchange) =
        serverSecurityContextRepository.save(exchange.exchange, null)
}
