package com.gooddata.oauth2.server

import java.net.URI
import mu.KotlinLogging
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.web.server.DefaultServerRedirectStrategy
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler
import org.springframework.web.util.UriComponentsBuilder
import reactor.core.publisher.Mono

/**
 * Realize logout if provider is Auth0
 * Inspired by https://auth0.com/docs/quickstart/webapp/java-spring-boot/01-login#add-logout-to-your-application
 *
 * @param clientRegistrationRepository the repository for client registrations
 * @param auth0CustomDomain if defined, the Auth0 is white-labeled by the custom domain name different
 * from the `*auth0.com`
 */
class Auth0LogoutHandler(
    private val clientRegistrationRepository: ReactiveClientRegistrationRepository,
    private val auth0CustomDomain: String?,
) : ServerLogoutHandler, ServerLogoutSuccessHandler {

    private val logger = KotlinLogging.logger {}
    private val redirectStrategy = DefaultServerRedirectStrategy()

    override fun logout(exchange: WebFilterExchange, authentication: Authentication?): Mono<Void> =
        Mono.justOrEmpty(authentication)
            .filter { it is OAuth2AuthenticationToken }
            .cast(OAuth2AuthenticationToken::class.java)
            .flatMap {
                logoutUrl(exchange.exchange.request).flatMap { url ->
                    redirectStrategy.sendRedirect(exchange.exchange, url)
                }
            }

    override fun onLogoutSuccess(exchange: WebFilterExchange, authentication: Authentication): Mono<Void> =
        logout(exchange, authentication)

    private fun logoutUrl(request: ServerHttpRequest): Mono<URI> =
        clientRegistrationRepository.findByRegistrationId(request.uri.host)
            .map { clientRegistration ->
                Pair(clientRegistration, clientRegistration.issuer())
            }.filter { (_, issuer) ->
                issuer.isAuth0() || issuer.hasCustomDomain()
            }.map { (clientRegistration, issuer) ->
                // workaround for STL-458: use URL from 'returnTo' query parameter if provided,
                // otherwise use default URL
                val returnTo = URI.create(request.returnToQueryParam()) ?: request.uri.baseUrl()
                buildLogoutUrl(issuer, clientRegistration.clientId, returnTo)
            }.doOnNext { logoutUrl ->
                logger.debug { "Auth0 logout URL: $logoutUrl" }
            }

    private fun ClientRegistration.issuer(): URI = providerDetails.configurationMetadata["issuer"].toString().toUri()

    private fun URI.hasCustomDomain(): Boolean = auth0CustomDomain != null && auth0CustomDomain == host

    private fun buildLogoutUrl(issuer: URI, clientId: String, returnTo: URI): URI =
        UriComponentsBuilder.fromHttpUrl("${issuer}v2/logout")
            .queryParam("client_id", clientId)
            // https://auth0.com/docs/authenticate/login/logout/redirect-users-after-logout
            .queryParam("returnTo", returnTo)
            .build()
            .toUri()
}
