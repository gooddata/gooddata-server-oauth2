/*
 * Copyright 2021 GoodData Corporation
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
package com.gooddata.oauth2.server.reactive

import com.gooddata.oauth2.server.common.AppLoginProperties
import com.gooddata.oauth2.server.common.AuthenticationStoreClient
import com.gooddata.oauth2.server.common.CachingProperties
import com.gooddata.oauth2.server.common.CaffeineClientRegistrationCache
import com.gooddata.oauth2.server.common.CaffeineJwkCache
import com.gooddata.oauth2.server.common.ClientRegistrationCache
import com.gooddata.oauth2.server.common.CookieSerializer
import com.gooddata.oauth2.server.common.CookieServiceProperties
import com.gooddata.oauth2.server.common.CorsConfigurations
import com.gooddata.oauth2.server.common.HostBasedClientRegistrationRepositoryProperties
import com.gooddata.oauth2.server.common.JwkCache
import com.gooddata.oauth2.server.common.OrganizationCorsConfigurationSource
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.autoconfigure.AutoConfigureBefore
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.security.oauth2.client.reactive.ReactiveOAuth2ClientAutoConfiguration
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.config.web.server.invoke
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoderFactory
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.logout.DelegatingServerLogoutHandler
import org.springframework.security.web.server.authentication.logout.LogoutWebFilter
import org.springframework.security.web.server.authentication.logout.SecurityContextServerLogoutHandler
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler
import org.springframework.security.web.server.context.ServerSecurityContextRepository
import org.springframework.security.web.server.util.matcher.NegatedServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers.pathMatchers
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource
import org.springframework.web.reactive.config.EnableWebFlux
import java.net.URI

@Configuration
@EnableConfigurationProperties(
    CookieServiceProperties::class,
    HostBasedClientRegistrationRepositoryProperties::class,
    AppLoginProperties::class,
    CachingProperties::class
)
@AutoConfigureBefore(ReactiveOAuth2ClientAutoConfiguration::class)
@ConditionalOnClass(EnableWebFlux::class)
class ServerOAuth2AutoConfiguration {

    /**
     * This cannot be on top-level configuration class as annotation would be processed even though configuration
     * would be disabled by conditionals.
     */
    @EnableWebFluxSecurity
    class EnabledSecurity

    @Bean
    fun cookieSerializer(
        cookieServiceProperties: CookieServiceProperties,
        client: ObjectProvider<AuthenticationStoreClient>,
    ) = CookieSerializer(
        cookieServiceProperties,
        client.`object`
    )

    @Bean
    fun cookieService(
        cookieServiceProperties: CookieServiceProperties,
        cookieSerializer: CookieSerializer
    ) = ReactiveCookieService(
        cookieServiceProperties,
        cookieSerializer
    )

    @Bean
    fun authorizedClientRepository(
        clientRegistrationRepository: ReactiveClientRegistrationRepository,
        cookieService: ReactiveCookieService,
    ): ServerOAuth2AuthorizedClientRepository =
        CookieServerOAuth2AuthorizedClientRepository(clientRegistrationRepository, cookieService)

    @Bean
    fun clientRegistrationRepository(
        client: ObjectProvider<AuthenticationStoreClient>,
        properties: HostBasedClientRegistrationRepositoryProperties,
        clientRegistrationCache: ClientRegistrationCache,
    ): ReactiveClientRegistrationRepository =
        HostBasedReactiveClientRegistrationRepository(client.`object`, properties, clientRegistrationCache)

    @ConditionalOnMissingBean(ClientRegistrationCache::class)
    @Bean
    fun clientRegistrationCache(cachingProperties: CachingProperties): ClientRegistrationCache =
        CaffeineClientRegistrationCache(
            cachingProperties.clientRegistrationMaxSize,
            cachingProperties.clientRegistrationExpireAfterWriteMinutes
        )

    @Bean
    fun serverSecurityContextRepository(
        clientRegistrationRepository: ReactiveClientRegistrationRepository,
        cookieService: ReactiveCookieService,
        reactiveDecoderFactory: ReactiveJwtDecoderFactory<ClientRegistration>
    ): ServerSecurityContextRepository =
        CookieServerSecurityContextRepository(clientRegistrationRepository, cookieService, reactiveDecoderFactory)

    @Bean
    fun reactiveJwtDecoderFactory(jwkCache: JwkCache): ReactiveJwtDecoderFactory<ClientRegistration> =
        JwkCachingReactiveDecoderFactory(jwkCache)

    @ConditionalOnMissingBean(JwkCache::class)
    @Bean
    fun jwkCache(cachingProperties: CachingProperties) =
        CaffeineJwkCache(cachingProperties.jwkMaxSize, cachingProperties.jwkExpireAfterWriteMinutes)

    @Bean
    fun corsConfigurationSource(
        organizationCorsConfigurationSource: OrganizationCorsConfigurationSource,
        globalCorsConfigurations: CorsConfigurations?,
        appLoginProperties: AppLoginProperties,
    ): CompositeCorsConfigurationSource = CompositeCorsConfigurationSource(
        UrlBasedCorsConfigurationSource().apply {
            globalCorsConfigurations?.configurations?.forEach { (pattern, config) ->
                registerCorsConfiguration(pattern, config)
            }
        },
        organizationCorsConfigurationSource,
        appLoginProperties.allowRedirect.toString()
    )

    @Bean
    fun organizationCorsConfigurationSource(
        authenticationStoreClient: AuthenticationStoreClient
    ) = OrganizationCorsConfigurationSource(authenticationStoreClient)

    @Bean
    @Suppress("LongParameterList", "LongMethod")
    fun springSecurityFilterChain(
        http: ServerHttpSecurity,
        oauth2ClientRepository: ServerOAuth2AuthorizedClientRepository,
        clientRegistrationRepository: ReactiveClientRegistrationRepository,
        cookieService: ReactiveCookieService,
        serverSecurityContextRepository: ServerSecurityContextRepository,
        client: ObjectProvider<AuthenticationStoreClient>,
        appLoginProperties: AppLoginProperties,
        userContextHolder: ObjectProvider<UserContextHolder<*>>,
        compositeCorsConfigurationSource: CompositeCorsConfigurationSource,
    ): SecurityWebFilterChain {
        val cookieServerRequestCache = CookieServerRequestCache(cookieService)
        val hostBasedAuthEntryPoint = HostBasedServerAuthenticationEntryPoint(cookieServerRequestCache)
        val logoutHandler = DelegatingServerLogoutHandler(
            SecurityContextServerLogoutHandler().apply {
                setSecurityContextRepository(serverSecurityContextRepository)
            },
            ServerLogoutHandler { exchange, authentication ->
                oauth2ClientRepository.removeAuthorizedClient(
                    exchange.exchange.request.uri.host, authentication, exchange.exchange
                )
            }
        )
        val logoutSuccessHandler = OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository).apply {
            setPostLogoutRedirectUri("{baseUrl}")
            setLogoutSuccessUrl(URI.create("/"))
        }

        return (http.securityContextRepository(serverSecurityContextRepository)) {
            securityMatcher {
                NegatedServerWebExchangeMatcher(
                    OrServerWebExchangeMatcher(
                        PathPatternParserServerWebExchangeMatcher("/actuator"),
                        PathPatternParserServerWebExchangeMatcher("/actuator/**"),
                        PathPatternParserServerWebExchangeMatcher("/login"),
                        PathPatternParserServerWebExchangeMatcher("/api/schemas/*", HttpMethod.GET),
                        PathPatternParserServerWebExchangeMatcher("/error", HttpMethod.GET),
                    )
                ).matches(it)
            }
            csrf {
                disable()
            }
            headers {
                contentTypeOptions {}
                cache {}
                frameOptions { disable() }
                hsts {}
            }
            oauth2ResourceServer {
                authenticationManagerResolver = BearerTokenReactiveAuthenticationManagerResolver(client.`object`)
            }
            oauth2Login {
                authorizationRequestRepository = CookieServerAuthorizationRequestRepository(cookieService)
                authorizedClientRepository = oauth2ClientRepository
                authenticationFailureHandler = ServerOAuth2FailureHandler()
            }
            exceptionHandling {
                authenticationEntryPoint = hostBasedAuthEntryPoint
            }
            authorizeExchange {
                authorize(anyExchange, authenticated)
            }
            requestCache {
                requestCache = cookieServerRequestCache
            }

            logout {
                this.logoutSuccessHandler = logoutSuccessHandler
                this.logoutHandler = logoutHandler
                requiresLogout = pathMatchers(HttpMethod.GET, "/logout")
            }
            addFilterBefore(PostLogoutNotAllowedWebFilter(), SecurityWebFiltersOrder.LOGOUT)
            addFilterAfter(
                UserContextWebFilter(
                    client.`object`,
                    hostBasedAuthEntryPoint,
                    logoutHandler,
                    userContextHolder.`object`
                ),
                SecurityWebFiltersOrder.LOGOUT
            )
            addFilterBefore(
                LogoutWebFilter().apply {
                    setLogoutSuccessHandler(logoutSuccessHandler)
                    setLogoutHandler(
                        DelegatingServerLogoutHandler(
                            logoutHandler,
                            LogoutAllServerLogoutHandler(client.`object`, userContextHolder.`object`),
                        )
                    )
                    setRequiresLogoutMatcher(pathMatchers(HttpMethod.GET, "/logout/all"))
                },
                SecurityWebFiltersOrder.EXCEPTION_TRANSLATION
            )
            addFilterAfter(
                AppLoginWebFilter(appLoginProperties, client.`object`),
                SecurityWebFiltersOrder.AUTHORIZATION
            )
            cors {
                this.configurationSource = compositeCorsConfigurationSource
            }
            oauth2Client {}
        }
    }
}
