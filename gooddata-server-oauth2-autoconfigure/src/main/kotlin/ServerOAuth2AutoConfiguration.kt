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

import com.gooddata.oauth2.server.oauth2.client.CustomAttrsAwareOauth2AuthorizationRequestResolver
import java.util.Base64
import org.springframework.beans.factory.ObjectProvider
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.AutoConfigureBefore
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.security.oauth2.client.reactive.ReactiveOAuth2ClientAutoConfiguration
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Import
import org.springframework.http.HttpMethod
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.config.web.server.ServerHttpSecurityDsl
import org.springframework.security.config.web.server.invoke
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator
import org.springframework.security.oauth2.client.authentication.OAuth2LoginReactiveAuthenticationManager
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeReactiveAuthenticationManager
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoderFactory
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.DelegatingServerAuthenticationSuccessHandler
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
        clientRegistrationCache: ClientRegistrationCache,
        authenticationStoreClient: ObjectProvider<AuthenticationStoreClient>
    ): ReactiveClientRegistrationRepository =
        HostBasedReactiveClientRegistrationRepository(
            properties,
            clientRegistrationCache,
            authenticationStoreClient.`object`
        )

    @ConditionalOnMissingBean(ClientRegistrationCache::class)
    @Bean
    fun clientRegistrationCache(cachingProperties: CachingProperties): ClientRegistrationCache =
        CaffeineClientRegistrationCache(
            cachingProperties.clientRegistrationMaxSize,
            cachingProperties.clientRegistrationExpireAfterWriteMinutes
        )

    @Bean
    fun repositoryAwareOidcTokensRefreshingService(
        refreshTokenResponseClient: ReactiveOAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest>,
        authorizedClientRepository: ServerOAuth2AuthorizedClientRepository,
    ) = RepositoryAwareOidcTokensRefreshingService(refreshTokenResponseClient, authorizedClientRepository)

    @Bean
    fun serverSecurityContextRepository(
        clientRegistrationRepository: ReactiveClientRegistrationRepository,
        cookieService: ReactiveCookieService,
        reactiveDecoderFactory: ReactiveJwtDecoderFactory<ClientRegistration>,
        repositoryAwareOidcTokensRefreshingService: RepositoryAwareOidcTokensRefreshingService,
        authorizedClientRepository: ServerOAuth2AuthorizedClientRepository,
    ): ServerSecurityContextRepository = CookieServerSecurityContextRepository(
        clientRegistrationRepository,
        cookieService,
        reactiveDecoderFactory,
        repositoryAwareOidcTokensRefreshingService,
        authorizedClientRepository,
    )

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
    ): CompositeCorsConfigurationSource = CompositeCorsConfigurationSource(
        UrlBasedCorsConfigurationSource().apply {
            globalCorsConfigurations?.configurations?.forEach { (pattern, config) ->
                registerCorsConfiguration(pattern, config)
            }
        },
        organizationCorsConfigurationSource
    )

    @Bean
    fun organizationCorsConfigurationSource(appProperties: AppLoginProperties) =
        OrganizationCorsConfigurationSource(appProperties.allowRedirect.toString())

    /**
     * By default, Spring Security fills the `state` query parameter value of the authorization request call
     * with the **base64-encoded 32-byte** random. It means that the base64 string needs to be aligned to the closest
     * multiple of 3 using the `=` sign. The "equal" sign is a reserved character in URL and must be URI-encoded (to
     * `%3D`).
     *
     * At least Amazon Cognito IdP does not encode this query parameter in the `Location` header after the successful
     * login. This results in the URL parsing error when the client application has `server.forward-headers-strategy`
     * Spring property set to the `framework` value (use `ForwardedHeaderTransformer` for rewriting URLs
     * based on `X-Forwarded*` headers).
     *
     * To avoid the problem mentioned above, we are changing the `state` generator to fill query parameters
     * with the **base64-URL-encoded 33-byte** random values.
     */
    @Bean
    fun urlSafeStateAuthorizationRequestResolver(
        clientRegistrationRepository: ReactiveClientRegistrationRepository
    ): ServerOAuth2AuthorizationRequestResolver {
        // ensures the URL-safe (encoded) Base64
        val base64Encoder = Base64.getUrlEncoder()
        // use the new state generator with "multiple of 3" bytes
        val stateKeyGenerator = Base64StringKeyGenerator(base64Encoder, URL_SAFE_STATE_KEY_BYTES)
        return DefaultServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository).apply {
            setAuthorizationRequestCustomizer { builder -> builder.state(stateKeyGenerator.generateKey()) }
        }
    }

    /**
     * Resolver which support OIDC federation.
     */
    @Bean
    fun federationAwareAuthorizationRequestResolver(
        urlSafeStateAuthorizationRequestResolver: ServerOAuth2AuthorizationRequestResolver,
        cookieService: ReactiveCookieService,
    ) = CustomAttrsAwareOauth2AuthorizationRequestResolver(urlSafeStateAuthorizationRequestResolver, cookieService)

    @Bean
    @Suppress("LongParameterList", "LongMethod")
    fun springSecurityFilterChain(
        serverHttpSecurity: ServerHttpSecurity,
        oauth2ClientRepository: ServerOAuth2AuthorizedClientRepository,
        clientRegistrationRepository: ReactiveClientRegistrationRepository,
        cookieService: ReactiveCookieService,
        serverSecurityContextRepository: ServerSecurityContextRepository,
        authenticationStoreClient: ObjectProvider<AuthenticationStoreClient>,
        auditClient: ObjectProvider<AuthenticationAuditClient>,
        appLoginProperties: AppLoginProperties,
        userContextHolder: ObjectProvider<UserContextHolder<*>>,
        userContextProvider: ObjectProvider<ReactorUserContextProvider>,
        compositeCorsConfigurationSource: CompositeCorsConfigurationSource,
        grantedAuthoritiesMapper: ObjectProvider<GrantedAuthoritiesMapper>,
        jwtDecoderFactory: ObjectProvider<ReactiveJwtDecoderFactory<ClientRegistration>>,
        loginAuthManager: ReactiveAuthenticationManager,
        federationAwareAuthorizationRequestResolver: ServerOAuth2AuthorizationRequestResolver,
        // TODO these properties serve as a temporary hack.
        //  So for now, we will keep this configuration property here.
        //  Can be moved elsewhere or even removed in the following library release.
        @Value("\${spring.security.oauth2.config.provider.auth0.customDomain:#{null}}") auth0CustomDomain: String?,
        @Value("\${spring.security.oauth2.config.provider.cognito.customDomain:#{null}}") cognitoCustomDomain: String?,
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
        val hostBasedAuthEntryPoint = HostBasedServerAuthenticationEntryPoint(serverRequestCache)

        val logoutHandler = DelegatingServerLogoutHandler(
            SecurityContextRepositoryLogoutHandler(serverSecurityContextRepository),
            ClientRepositoryLogoutHandler(oauth2ClientRepository),
            JwtAuthenticationLogoutHandler(authenticationStoreClient.`object`)
        )

        val logoutSuccessHandler = DelegatingServerLogoutSuccessHandler(
            // Order of handlers is important!
            QueryParamOidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository, "{baseUrl}", "/"),
            // Keep custom OIDC handlers as last in OIDC handlers
            CognitoLogoutHandler(clientRegistrationRepository, cognitoCustomDomain),
            Auth0LogoutHandler(clientRegistrationRepository, auth0CustomDomain),
            JwtAuthenticationLogoutHandler(authenticationStoreClient.`object`),
            client = authenticationStoreClient.`object`,
            auditClient = auditClient.`object`,
        )

        val authSuccessHandler = DelegatingServerAuthenticationSuccessHandler(
            JitProvisioningAuthenticationSuccessHandler(authenticationStoreClient.`object`),
            LoggingRedirectServerAuthenticationSuccessHandler(
                authenticationStoreClient.`object`,
                auditClient.`object`,
                serverRequestCache
            )
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
                authenticationManagerResolver = BearerTokenReactiveAuthenticationManagerResolver(
                    authenticationStoreClient.`object`,
                    auditClient.`object`
                )
            }
            oauth2Login {
                authorizationRequestRepository = CookieServerAuthorizationRequestRepository(cookieService)
                authorizedClientRepository = oauth2ClientRepository
                authenticationFailureHandler = ServerOAuth2FailureHandler(auditClient.`object`)
                authenticationManager = loginAuthManager
                authorizationRequestResolver = federationAwareAuthorizationRequestResolver
                authenticationSuccessHandler = authSuccessHandler
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
                    OidcAuthenticationProcessor(
                        authenticationStoreClient.`object`,
                        hostBasedAuthEntryPoint,
                        logoutHandler,
                        userContextProvider.`object`,
                        oauth2ClientRepository,
                    ),
                    JwtAuthenticationProcessor(
                        authenticationStoreClient.`object`,
                        logoutHandler,
                        userContextProvider.`object`
                    ),
                    UserContextAuthenticationProcessor(userContextProvider.`object`)
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
                                authenticationStoreClient.`object`,
                                userContextHolder.`object`
                            ),
                        )
                    )
                    setRequiresLogoutMatcher(pathMatchers(HttpMethod.GET, "/logout/all"))
                },
                SecurityWebFiltersOrder.EXCEPTION_TRANSLATION
            )
            addFilterAt(
                AppLoginWebFilter(appLoginRedirectProcessor),
                SecurityWebFiltersOrder.LAST
            )
            addFilterAt(
                OrganizationWebFilter(
                    authenticationStoreClient.`object`
                ),
                SecurityWebFiltersOrder.FIRST
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
            return CustomDelegatingReactiveAuthenticationManager(oauth2Manager)
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
        return CustomDelegatingReactiveAuthenticationManager(oidc, oauth2Manager)
    }

    companion object {
        /**
         * Number of bytes for having the URL-safe `state` query parameter values in auth. requests.
         *
         * The value should always be the "multiple of 3".
         *
         * @see ServerOAuth2AutoConfiguration.urlSafeStateAuthorizationRequestResolver
         */
        private const val URL_SAFE_STATE_KEY_BYTES = 33
    }
}

fun ServerHttpSecurity.configure(httpConfiguration: ServerHttpSecurityDsl.() -> Unit): SecurityWebFilterChain =
    this.invoke(httpConfiguration)
