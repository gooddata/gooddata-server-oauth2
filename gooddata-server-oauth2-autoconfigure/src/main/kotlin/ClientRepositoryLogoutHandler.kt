/*
 * (C) 2022 GoodData Corporation
 */
package com.gooddata.oauth2.server

import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler
import reactor.core.publisher.Mono

class ClientRepositoryLogoutHandler(
    private val oauth2ClientRepository: ServerOAuth2AuthorizedClientRepository
) : ServerLogoutHandler {

    override fun logout(exchange: WebFilterExchange, authentication: Authentication?): Mono<Void> =
        Mono.justOrEmpty(authentication)
            .filter { it is OAuth2AuthenticationToken }
            .flatMap { token ->
                oauth2ClientRepository.removeAuthorizedClient(
                    exchange.exchange.request.uri.host,
                    token,
                    exchange.exchange
                )
            }
}
