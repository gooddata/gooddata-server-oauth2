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
package com.gooddata.oauth2.server.servlet

import com.gooddata.oauth2.server.common.AuthenticationStoreClient
import com.gooddata.oauth2.server.common.CookieSerializer
import com.gooddata.oauth2.server.common.CookieServiceProperties
import com.gooddata.oauth2.server.common.HostBasedClientRegistrationRepositoryProperties
import org.springframework.boot.autoconfigure.AutoConfigureBefore
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.security.oauth2.client.servlet.OAuth2ClientAutoConfiguration
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.jwt.JwtDecoderFactory
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler
import org.springframework.security.web.authentication.logout.LogoutFilter
import org.springframework.security.web.authentication.logout.LogoutHandler
import org.springframework.security.web.context.SecurityContextRepository
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.NegatedRequestMatcher
import org.springframework.security.web.util.matcher.OrRequestMatcher
import javax.servlet.Filter

@Configuration
@EnableConfigurationProperties(CookieServiceProperties::class, HostBasedClientRegistrationRepositoryProperties::class)
@AutoConfigureBefore(OAuth2ClientAutoConfiguration::class)
@ConditionalOnClass(Filter::class)
class OAuth2AutoConfiguration(
    private val authenticationStoreClient: AuthenticationStoreClient,
    private val userContextHolder: UserContextHolder,
    private val cookieServiceProperties: CookieServiceProperties,
    private val hostBasedClientRegistrationRepositoryProperties: HostBasedClientRegistrationRepositoryProperties,
) : WebSecurityConfigurerAdapter() {

    /**
     * This cannot be on top-level configuration class as annotation would be processed even though configuration
     * would be disabled by conditionals.
     */
    @EnableWebSecurity
    class EnabledSecurity

    @Bean
    fun cookieSerializer() = CookieSerializer(cookieServiceProperties, authenticationStoreClient)

    @Bean
    fun cookieService() =
        CookieService(cookieServiceProperties, cookieSerializer())

    @Bean
    fun authorizedClientRepository(): OAuth2AuthorizedClientRepository =
        CookieOAuth2AuthorizedClientRepository(clientRegistrationRepository(), cookieService())

    @Bean
    fun clientRegistrationRepository(): ClientRegistrationRepository =
        HostBasedClientRegistrationRepository(
            authenticationStoreClient,
            hostBasedClientRegistrationRepositoryProperties,
        )

    @Bean
    fun securityContextRepository(): SecurityContextRepository =
        CookieSecurityContextRepository(clientRegistrationRepository(), cookieService())

    @Bean
    fun jwtDecoderFactory(): JwtDecoderFactory<ClientRegistration> = NoCachingDecoderFactory()

    @Suppress("LongMethod")
    override fun configure(http: HttpSecurity) {
        val cookieRequestCache = CookieRequestCache(cookieService())
        val authorizedClientRepository = authorizedClientRepository()
        val authenticationEntryPoint = HostBasedAuthenticationEntryPoint(cookieRequestCache)
        val logoutHandler = CompositeLogoutHandler(
            SecurityContextClearingLogoutHandler(securityContextRepository()),
            LogoutHandler { request, response, authentication ->
                authorizedClientRepository.removeAuthorizedClient(
                    request.serverName, authentication, request, response
                )
            }
        )

        http
            .requestMatchers {
                it.requestMatchers(
                    NegatedRequestMatcher(
                        OrRequestMatcher(
                            AntPathRequestMatcher("/actuator"),
                            AntPathRequestMatcher("/actuator/**"),
                            AntPathRequestMatcher("/login"),
                            AntPathRequestMatcher("/api/schemas/*", HttpMethod.GET.name),
                            AntPathRequestMatcher("/error", HttpMethod.GET.name),
                        )
                    )
                )
            }
            .oauth2ResourceServer {
                it.authenticationManagerResolver(BearerTokenAuthenticationManagerResolver(authenticationStoreClient))
            }
            .oauth2Login {
                it.authorizationEndpoint { endpointConfig ->
                    endpointConfig.authorizationRequestRepository(CookieAuthorizationRequestRepository(cookieService()))
                }
                it.authorizedClientRepository(authorizedClientRepository)
                it.successHandler(
                    CookieAndSavedRequestAwareAuthenticationSuccessHandler(securityContextRepository()).apply {
                        setRequestCache(cookieRequestCache)
                    }
                )
            }
            .exceptionHandling {
                it.authenticationEntryPoint(authenticationEntryPoint)
            }
            .authorizeRequests {
                it.anyRequest().authenticated()
            }
            .requestCache {
                it.requestCache(cookieRequestCache)
            }
            .securityContext {
                it.securityContextRepository(securityContextRepository())
            }
            .csrf {
                it.disable()
            }
            .headers {
                it.contentTypeOptions()
                it.cacheControl()
                it.httpStrictTransportSecurity()
            }
            .logout {
                it.logoutSuccessHandler(
                    OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository()).apply {
                        setPostLogoutRedirectUri("{baseUrl}")
                    }
                )
                it.addLogoutHandler(
                    logoutHandler
                )
                it.logoutRequestMatcher(AntPathRequestMatcher("/logout", "GET"))
            }
            .addFilterBefore(PostLogoutNotAllowedFilter(), LogoutFilter::class.java)
            .addFilterBefore(
                ResponseStatusExceptionHandlingFilter(),
                BearerTokenAuthenticationFilter::class.java,
            )
            .addFilterAfter(
                UserContextFilter(
                    authenticationStoreClient, authenticationEntryPoint, logoutHandler, userContextHolder
                ),
                ExceptionTranslationFilter::class.java
            )
            .oauth2Client()
    }
}
