/*
 * Copyright 2022 GoodData Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.gooddata.oauth2.server

import kotlinx.coroutines.reactor.mono
import mu.KotlinLogging
import org.springframework.http.HttpMethod
import org.springframework.security.web.server.DefaultServerRedirectStrategy
import org.springframework.security.web.server.util.matcher.AndServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import org.springframework.web.util.UriComponentsBuilder
import reactor.core.publisher.Mono
import reactor.kotlin.core.publisher.switchIfEmpty
import java.net.URI

/**
 * [WebFilter] responsible of handling GET requests to `/appLogin?redirectTo={redirectTo}` URIs. When such URI is
 * requested filter uses `redirectTo` query param and responds with redirect to it.
 *
 * `redirectTo` URI is normalized, if relative URI is passed it is used, if absolute URI is passed it is checked
 * against allowed origin from properties.
 *
 * This [WebFilter] is in place mainly to allow JS apps to benefit from server-side OIDC authentication.
 *
 * _NOTE_: this filter is called only when the session is already authenticated
 */
class AppLoginWebFilter(private val appLoginRedirectProcessor: AppLoginRedirectProcessor) : WebFilter {

    private val redirectStrategy = DefaultServerRedirectStrategy()

    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> =
        appLoginRedirectProcessor.process(
            exchange,
            { redirectUri -> redirectStrategy.sendRedirect(exchange, URI.create(redirectUri)) },
            { chain.filter(exchange) }
        )
}

/**
 * Processes [AppLoginUri.REDIRECT_TO] query param for a web request called against [AppLoginUri.PATH]. In the case
 * that the request is not called against this path or does not fulfill [AppLoginUri.REDIRECT_TO] query param
 * conditions, the processing is skipped and the default fallback is used.
 */
class AppLoginRedirectProcessor(
    private val properties: AppLoginProperties,
    private val authenticationStoreClient: AuthenticationStoreClient,
) {
    private val logger = KotlinLogging.logger {}

    /**
     * Matches exchanges with [AppLoginUri.REDIRECT_TO] query parameter fulfilling following rules:
     * * Parameter value must be a valid URL string.
     * * The URL is a relative path starting with `/` or its domain hostname is globally (via Spring configuration
     *   properties) or organization-based (via [com.gooddata.oauth2.server.Organization.allowedOrigins]
     *   configuration) allowed host.
     *
     * If the exchange matches, [ServerWebExchangeMatcher.MatchResult.match] containing the [AppLoginUri.REDIRECT_TO]
     * variable with the value of the [AppLoginUri.REDIRECT_TO] parameter as URL decoded string is returned. Otherwise,
     * the matcher returns [ServerWebExchangeMatcher.MatchResult.notMatch].
     */
    private val appLoginRedirectToMatcher = ServerWebExchangeMatcher { serverWebExchange ->
        serverWebExchange.redirectToOrEmpty()
            .filterWhen { redirectTo -> canRedirect(redirectTo, serverWebExchange) }
            .flatMap { redirectTo ->
                ServerWebExchangeMatcher.MatchResult.match(
                    mapOf(AppLoginUri.REDIRECT_TO to redirectTo.toASCIIString())
                )
            }
            .switchIfEmpty(ServerWebExchangeMatcher.MatchResult.notMatch())
    }

    /**
     * Matches that the web request:
     * * Is [HttpMethod.GET] for path [AppLoginUri.PATH]
     * * Fulfills conditions defined by [appLoginRedirectToMatcher]
     */
    private val appLoginMatcher = AndServerWebExchangeMatcher(
        ServerWebExchangeMatchers.pathMatchers(HttpMethod.GET, AppLoginUri.PATH),
        appLoginRedirectToMatcher
    )

    /**
     * Processes this [exchange] by applying a function and returns empty [Mono] producer. If the HTTP request matches
     * the [appLoginMatcher], then its [AppLoginUri.REDIRECT_TO] query parameter value is processed
     * by the [redirectToProcessor]. Otherwise, the [emptyRedirectToFallback] is used.
     *
     * @param exchange HTTP exchange containing request/response
     * @param redirectToProcessor the function for processing [AppLoginUri.REDIRECT_TO] query parameter
     * @param emptyRedirectToFallback the fallback function if the [AppLoginUri.REDIRECT_TO] could not be fetched from
     * the [exchange]
     * @return empty [Mono]
     */
    fun process(
        exchange: ServerWebExchange,
        redirectToProcessor: (String) -> Mono<Void>,
        emptyRedirectToFallback: () -> Mono<Void>,
    ): Mono<Void> = appLoginMatcher.matches(exchange)
        .filter { matchResult -> matchResult.isMatch }
        // we cannot use the flatMap here because the process returns the empty Mono
        .map { matchResult ->
            val redirectUri = matchResult.variables[AppLoginUri.REDIRECT_TO] as String
            redirectToProcessor.invoke(redirectUri)
        }
        // we need to use the deferred Mono here (used extension function internally uses it for the wrapping)
        .switchIfEmpty { Mono.just(emptyRedirectToFallback.invoke()) }
        // we need to subscribe to the underlying Mono to invoke sendRedirect or filter chain
        .flatMap { it }

    private fun ServerWebExchange.redirectToOrEmpty(): Mono<URI> {
        val redirectTo = request.queryParams[AppLoginUri.REDIRECT_TO]?.firstOrNull()
        return if (redirectTo == null) {
            logger.trace { "Query param \"${AppLoginUri.REDIRECT_TO}\" not found" }
            Mono.empty()
        } else {
            Mono.defer {
                Mono.just(URI.create(redirectTo).normalize())
            }.onErrorResume { exception ->
                logger.debug { "URL normalization error: $exception" }
                Mono.empty()
            }
        }
    }

    private fun canRedirect(redirectTo: URI, serverWebExchange: ServerWebExchange): Mono<Boolean> {
        val uri = redirectTo.normalizeToRedirectToPattern()
        val organizationHost = serverWebExchange.request.uri.host
        return Mono.just(true)
            .filter { uri.isAllowedGlobally() || redirectTo.isLocal() }
            .switchIfEmpty(uri.isAllowedForOrganization(organizationHost))
            .doOnNext { canRedirect ->
                if (!canRedirect) {
                    logger.trace { "URI \"$uri\" can't be redirected" }
                }
            }
    }

    private fun URI.normalizeToRedirectToPattern() =
        UriComponentsBuilder.fromUri(this)
            .replacePath(null)
            .replaceQuery(null)
            .fragment(null)
            .build().toUri()

    private fun URI.isAllowedForOrganization(organizationHost: String): Mono<Boolean> =
        mono { authenticationStoreClient.getOrganizationByHostname(organizationHost) }
            .flatMap { organization -> Mono.justOrEmpty(organization.allowedOrigins?.map(::URI)) }
            .map { allowedOrigins -> allowedOrigins.any { this == it.normalizeToRedirectToPattern() } }
            .defaultIfEmpty(false)

    private fun URI.isAllowedGlobally() = this == properties.allowRedirect

    private fun URI.isLocal() = normalizeToRedirectToPattern() == EMPTY_URI && path.startsWith("/")

    companion object {
        private val EMPTY_URI = URI.create("")
    }
}

/**
 * Contains constants defining `appLogin` URL and its corresponding query parameter names.
 */
object AppLoginUri {
    const val PATH = "/appLogin"
    internal const val REDIRECT_TO = "redirectTo"
}

/**
 * Writes "appLogin" requests into corresponding HTTP cookies.
 */
class AppLoginCookieRequestCacheWriter(private val cookieService: ReactiveCookieService) {
    /**
     * Saves the [redirectUri] from the [AppLoginUri.REDIRECT_TO] query parameter value into the [SPRING_REDIRECT_URI]
     * HTTP response set-cookie.
     *
     * @param exchange the server HTTP exchange containing request/response
     * @param redirectUri the value of the [AppLoginUri.REDIRECT_TO] query parameter
     */
    fun saveRequest(exchange: ServerWebExchange, redirectUri: String) {
        cookieService.createCookie(exchange, SPRING_REDIRECT_URI, redirectUri)
    }
}
