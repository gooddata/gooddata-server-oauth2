/*
 * Copyright 2025 GoodData Corporation
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

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.AutoConfigureBefore
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.security.oauth2.client.reactive.ReactiveOAuth2ClientAutoConfiguration
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Import
import org.springframework.core.annotation.Order
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.logout.DelegatingServerLogoutHandler
import org.springframework.security.web.server.context.ServerSecurityContextRepository
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher
import org.springframework.web.reactive.config.EnableWebFlux
import reactor.core.publisher.Mono

@AutoConfiguration
@EnableConfigurationProperties(
    CookieServiceProperties::class,
    HostBasedClientRegistrationRepositoryProperties::class,
    AppLoginProperties::class,
    CachingProperties::class
)
@AutoConfigureBefore(ReactiveOAuth2ClientAutoConfiguration::class)
@ConditionalOnClass(EnableWebFlux::class)
@Import(ReactiveCommunicationClientsConfiguration::class)
// TODO SHOULD WE EMBED THIS AUTO CONFIGURATION INTO THE GOODDATA SERVER OAUTH2 AUTO CONFIGURATION?
class AlternativeServerOAuth2AutoConfiguration {

    companion object {
        private val logger = LoggerFactory.getLogger(AlternativeServerOAuth2AutoConfiguration::class.java)
    }

    /**
     * Enables WebFlux Security for alternative OAuth configuration.
     * This ensures SecurityWebFilterChain beans are properly recognized.
     */
    @EnableWebFluxSecurity
    class AlternativeEnabledSecurity

    @Bean
    fun idpWebFilter(): IdpWebFilter = IdpWebFilter()

    @Bean
    @Order(1) // Higher priority than main security chain
    fun alternativeSecurityFilterChain(
        serverHttpSecurity: ServerHttpSecurity,
        serverSecurityContextRepository: ServerSecurityContextRepository,
        authorizedClientRepository: ServerOAuth2AuthorizedClientRepository,
        idpWebFilter: IdpWebFilter,
        cookieService: ReactiveCookieService,
        authenticationStoreClient: ObjectProvider<AuthenticationStoreClient>,
        auditClient: ObjectProvider<AuthenticationAuditClient>,
        userContextProvider: ObjectProvider<ReactorUserContextProvider>,
        loginAuthManager: ReactiveAuthenticationManager,
        compositeCorsConfigurationSource: CompositeCorsConfigurationSource,
        appLoginProperties: AppLoginProperties,
        federationAwareAuthorizationRequestResolver: ServerOAuth2AuthorizationRequestResolver,
    ): SecurityWebFilterChain {

        val appLoginRedirectProcessor = AppLoginRedirectProcessor(
            compositeCorsConfigurationSource,
            appLoginProperties.allowRedirect
        )

        val serverRequestCache = DelegatingServerRequestCache(
            CookieServerRequestCache(cookieService),
            AppLoginCookieRequestCacheWriter(cookieService),
            appLoginRedirectProcessor,
        )

        val idpBasedAuthenticationEntryPoint = AlternativeServerAuthenticationEntryPoint(serverRequestCache)

        return serverHttpSecurity.securityContextRepository(serverSecurityContextRepository).configure {
            securityMatcher { serverWebExchange ->
                val requestPath = serverWebExchange.request.uri.path
                // Match the actual API pattern that needs alternative authentication
                val matches = PathPatternParserServerWebExchangeMatcher(
                    "/api/v1/actions/organization/testIdp/**"
                ).matches(serverWebExchange)

                matches.flatMap {
                    logger.info("DEBUG: 🔄 Alternative Security Chain - Path: {} | Matches: {}", requestPath, it.isMatch)
                    Mono.just(it)
                }
            }
            exceptionHandling {
                authenticationEntryPoint = idpBasedAuthenticationEntryPoint
            }
            authorizeExchange {
                authorize(anyExchange, authenticated)
            }
            addFilterAt(
                idpWebFilter,
                SecurityWebFiltersOrder.FIRST
            )
            addFilterAt(
                OrganizationWebFilter(
                    authenticationStoreClient.`object`
                ),
                SecurityWebFiltersOrder.FIRST
            )
            // Add the UserContextWebFilter to set up AuthContext after authentication
            // TODO USE ONLY PROCESSORS THAT ARE NEEDED/USED
            addFilterAfter(
                UserContextWebFilter(
                    OidcAuthenticationProcessor(
                        authenticationStoreClient.`object`,
                        idpBasedAuthenticationEntryPoint, // Use alternative entry point
                        DelegatingServerLogoutHandler(
                            // Create a minimal logout handler for the alternative chain
                            SecurityContextRepositoryLogoutHandler(serverSecurityContextRepository)
                        ),
                        userContextProvider.`object`,
                        authorizedClientRepository,
                    ),
                    JwtAuthenticationProcessor(
                        authenticationStoreClient.`object`,
                        DelegatingServerLogoutHandler(
                            SecurityContextRepositoryLogoutHandler(serverSecurityContextRepository)
                        ),
                        userContextProvider.`object`
                    ),
                    UserContextAuthenticationProcessor(userContextProvider.`object`)
                ),
                SecurityWebFiltersOrder.LOGOUT
            )
        }
    }
}
