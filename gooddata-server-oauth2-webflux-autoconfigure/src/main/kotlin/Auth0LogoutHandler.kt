package com.gooddata.oauth2.server.reactive

import mu.KotlinLogging
import org.springframework.http.HttpRequest
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.web.server.DefaultServerRedirectStrategy
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler
import org.springframework.web.util.UriComponentsBuilder
import reactor.core.publisher.Mono
import java.net.URI

/**
 * Realize logout if provider is Auth0
 * Inspired by https://auth0.com/docs/quickstart/webapp/java-spring-boot/01-login#add-logout-to-your-application
 */
class Auth0LogoutHandler(
    private val clientRegistrationRepository: ReactiveClientRegistrationRepository
) : ServerLogoutHandler, ServerLogoutSuccessHandler {

    private val logger = KotlinLogging.logger {}
    private val redirectStrategy = DefaultServerRedirectStrategy()

    override fun logout(exchange: WebFilterExchange, authentication: Authentication): Mono<Void> =
        logoutUrl(exchange.exchange.request)
            .flatMap { url ->
                redirectStrategy.sendRedirect(exchange.exchange, url)
            }

    override fun onLogoutSuccess(exchange: WebFilterExchange, authentication: Authentication): Mono<Void> =
        logout(exchange, authentication)

    private fun logoutUrl(request: HttpRequest): Mono<URI> =
        clientRegistrationRepository.findByRegistrationId(request.uri.host)
            .map { clientRegistration ->
                Pair(clientRegistration, clientRegistration.issuer())
            }.filter { (_, issuer) ->
                issuer.isAuth0()
            }.map { (clientRegistration, issuer) ->
                buildLogoutUrl(issuer, clientRegistration.clientId, request.uri.baseUrl())
            }.doOnNext { logoutUrl ->
                logger.debug { "Auth0 logout URL: $logoutUrl" }
            }

    private fun ClientRegistration.issuer(): URI = providerDetails.configurationMetadata["issuer"].toString().toUri()

    private fun buildLogoutUrl(issuer: URI, clientId: String, returnTo: URI): URI =
        UriComponentsBuilder.fromHttpUrl("${issuer}v2/logout")
            .queryParam("client_id", clientId)
            .queryParam("returnTo", returnTo)
            .build()
            .toUri()
}
