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
package com.gooddata.oauth2.server

import org.springframework.beans.factory.ObjectProvider
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.AutoConfigureBefore
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.security.oauth2.client.reactive.ReactiveOAuth2ClientAutoConfiguration
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import
import org.springframework.http.HttpMethod
import org.springframework.security.authentication.DelegatingReactiveAuthenticationManager
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.config.web.server.ServerHttpSecurityDsl
import org.springframework.security.config.web.server.invoke
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper
import org.springframework.security.oauth2.client.authentication.OAuth2LoginReactiveAuthenticationManager
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeReactiveAuthenticationManager
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoderFactory
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.logout.DelegatingServerLogoutHandler
import org.springframework.security.web.server.authentication.logout.LogoutWebFilter
import org.springframework.security.web.server.context.ServerSecurityContextRepository
import org.springframework.security.web.server.util.matcher.NegatedServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers.pathMatchers
import org.springframework.util.ClassUtils
import org.springframework.web.client.RestTemplate
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
@Import(ReactiveCommunicationClientsConfiguration::class)
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
        authenticationStoreClient: ObjectProvider<AuthenticationStoreClient>,
    ) = CookieSerializer(
        cookieServiceProperties,
        authenticationStoreClient.`object`
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
        clientRegistrationBuilderCache: ClientRegistrationBuilderCache,
    ): ReactiveClientRegistrationRepository =
        HostBasedReactiveClientRegistrationRepository(client.`object`, properties, clientRegistrationBuilderCache)

    @ConditionalOnMissingBean(ClientRegistrationBuilderCache::class)
    @Bean
    fun clientRegistrationCache(cachingProperties: CachingProperties): ClientRegistrationBuilderCache =
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
    fun reactiveJwtDecoderFactory(
        jwkCache: JwkCache,
        restTemplate: RestTemplate
    ): ReactiveJwtDecoderFactory<ClientRegistration> =
        JwkCachingReactiveDecoderFactory(jwkCache, null, restTemplate)

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
        serverHttpSecurity: ServerHttpSecurity,
        oauth2ClientRepository: ServerOAuth2AuthorizedClientRepository,
        clientRegistrationRepository: ReactiveClientRegistrationRepository,
        cookieService: ReactiveCookieService,
        serverSecurityContextRepository: ServerSecurityContextRepository,
        authenticationStoreClients: ObjectProvider<AuthenticationStoreClient>,
        appLoginProperties: AppLoginProperties,
        userContextHolder: ObjectProvider<UserContextHolder<*>>,
        compositeCorsConfigurationSource: CompositeCorsConfigurationSource,
        grantedAuthoritiesMapper: ObjectProvider<GrantedAuthoritiesMapper>,
        jwtDecoderFactory: ObjectProvider<ReactiveJwtDecoderFactory<ClientRegistration>>,
        loginAuthManager: ReactiveAuthenticationManager,
        // TODO the property serves for a temporary hack.
        //  So for now, we will keep this configuration property here.
        //  Can be moved elsewhere or even removed in the following library release.
        @Value("\${spring.security.oauth2.config.provider.auth0.customDomain:#{null}}") auth0CustomDomain: String?,
    ): SecurityWebFilterChain {
        val appLoginRedirectProcessor = AppLoginRedirectProcessor(
            appLoginProperties,
            authenticationStoreClients.`object`,
        )
        val serverRequestCache = DelegatingServerRequestCache(
            CookieServerRequestCache(cookieService),
            AppLoginCookieRequestCacheWriter(cookieService),
            appLoginRedirectProcessor,
        )
        val hostBasedAuthEntryPoint = HostBasedServerAuthenticationEntryPoint(serverRequestCache)

        val logoutHandler = DelegatingServerLogoutHandler(
            SecurityContextRepositoryLogoutHandler(serverSecurityContextRepository),
            ClientRepositoryLogoutHandler(oauth2ClientRepository),
        )

        val logoutSuccessHandler = DelegatingServerLogoutSuccessHandler(
            // Order of handlers is important!
            OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository).apply {
                setPostLogoutRedirectUri("{baseUrl}")
                setLogoutSuccessUrl(URI.create("/"))
            },
            // Keep Auth0 handler as last one
            Auth0LogoutHandler(clientRegistrationRepository, auth0CustomDomain),
        )

        return serverHttpSecurity.securityContextRepository(serverSecurityContextRepository).configure {
            securityMatcher { serverWebExchange ->
                NegatedServerWebExchangeMatcher(
                    OrServerWebExchangeMatcher(
                        PathPatternParserServerWebExchangeMatcher("/actuator"),
                        PathPatternParserServerWebExchangeMatcher("/actuator/**"),
                        PathPatternParserServerWebExchangeMatcher("/login"),
                        PathPatternParserServerWebExchangeMatcher("/error", HttpMethod.GET),
                        PathPatternParserServerWebExchangeMatcher(OPEN_API_SCHEMA_PATTERN, HttpMethod.GET),
                        PathPatternParserServerWebExchangeMatcher(API_VERSION, HttpMethod.GET),
                    )
                ).matches(serverWebExchange)
            }
            cors {
                this@cors.configurationSource = compositeCorsConfigurationSource
            }
            csrf {
                disable()
            }
            headers {
                contentTypeOptions { }
                cache { }
                frameOptions { disable() }
                hsts { }
            }
            oauth2ResourceServer {
                authenticationManagerResolver =
                    BearerTokenReactiveAuthenticationManagerResolver(authenticationStoreClients.`object`)
            }
            oauth2Login {
                authorizationRequestRepository = CookieServerAuthorizationRequestRepository(cookieService)
                authorizedClientRepository = oauth2ClientRepository
                authenticationFailureHandler = ServerOAuth2FailureHandler()
                authenticationManager = loginAuthManager
            }
            oauth2Client { }
            exceptionHandling {
                authenticationEntryPoint = hostBasedAuthEntryPoint
            }
            authorizeExchange {
                authorize(anyExchange, authenticated)
            }
            requestCache {
                requestCache = serverRequestCache
            }
            logout {
                this.logoutSuccessHandler = logoutSuccessHandler
                this.logoutHandler = logoutHandler
                requiresLogout = pathMatchers(HttpMethod.GET, "/logout")
            }
            addFilterBefore(PostLogoutNotAllowedWebFilter(), SecurityWebFiltersOrder.LOGOUT)
            addFilterAfter(
                UserContextWebFilter(
                    authenticationStoreClients.`object`,
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
                            LogoutAllServerLogoutHandler(
                                authenticationStoreClients.`object`,
                                userContextHolder.`object`
                            ),
                        )
                    )
                    setRequiresLogoutMatcher(pathMatchers(HttpMethod.GET, "/logout/all"))
                },
                SecurityWebFiltersOrder.EXCEPTION_TRANSLATION
            )
            addFilterAfter(
                AppLoginWebFilter(appLoginRedirectProcessor),
                SecurityWebFiltersOrder.AUTHORIZATION
            )
        }
    }

    /**
     * Original:
     * [org.springframework.security.config.web.server.ServerHttpSecurity.OAuth2LoginSpec.createDefault]
     */
    @Bean
    fun loginAuthManager(
        grantedAuthoritiesMapper: ObjectProvider<GrantedAuthoritiesMapper>,
        jwtDecoderFactory: ObjectProvider<ReactiveJwtDecoderFactory<ClientRegistration>>,
        authCodeAccessTokenResponseClient: ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>,
        oauth2UserService: ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User>,
        oidcUserService: ReactiveOAuth2UserService<OidcUserRequest, OidcUser>
    ): ReactiveAuthenticationManager {
        val oauth2Manager =
            OAuth2LoginReactiveAuthenticationManager(authCodeAccessTokenResponseClient, oauth2UserService)
        val authoritiesMapper = grantedAuthoritiesMapper.ifAvailable
        if (authoritiesMapper != null) {
            oauth2Manager.setAuthoritiesMapper(authoritiesMapper)
        }
        val oidcAuthenticationProviderEnabled = ClassUtils.isPresent(
            "org.springframework.security.oauth2.jwt.JwtDecoder",
            this.javaClass.classLoader
        )
        if (!oidcAuthenticationProviderEnabled) {
            return oauth2Manager
        }
        val oidc = OidcAuthorizationCodeReactiveAuthenticationManager(
            authCodeAccessTokenResponseClient,
            oidcUserService
        )
        jwtDecoderFactory.ifAvailable?.let {
            oidc.setJwtDecoderFactory(it)
        }
        if (authoritiesMapper != null) {
            oidc.setAuthoritiesMapper(authoritiesMapper)
        }
        return DelegatingReactiveAuthenticationManager(oidc, oauth2Manager)
    }
}

fun ServerHttpSecurity.configure(httpConfiguration: ServerHttpSecurityDsl.() -> Unit): SecurityWebFilterChain =
    this.invoke(httpConfiguration)
