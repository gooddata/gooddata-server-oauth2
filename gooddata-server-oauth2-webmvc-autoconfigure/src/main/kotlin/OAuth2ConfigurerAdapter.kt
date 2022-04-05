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
package com.gooddata.oauth2.server.servlet

import com.gooddata.oauth2.server.common.AppLoginProperties
import com.gooddata.oauth2.server.common.AuthenticationStoreClient
import com.gooddata.oauth2.server.common.CorsConfigurations
import com.gooddata.oauth2.server.common.OrganizationCorsConfigurationSource
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.autoconfigure.AutoConfigureBefore
import org.springframework.boot.autoconfigure.security.oauth2.client.servlet.OAuth2ClientAutoConfiguration
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.web.servlet.invoke
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler
import org.springframework.security.web.authentication.logout.LogoutFilter
import org.springframework.security.web.authentication.logout.LogoutHandler
import org.springframework.security.web.context.SecurityContextRepository
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.NegatedRequestMatcher
import org.springframework.security.web.util.matcher.OrRequestMatcher
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Configuration
@EnableConfigurationProperties(
    AppLoginProperties::class,
)
@AutoConfigureBefore(OAuth2ClientAutoConfiguration::class)
class OAuth2ConfigurerAdapter(
    private val authenticationStoreClient: ObjectProvider<AuthenticationStoreClient>,
    private val userContextHolder: ObjectProvider<UserContextHolder>,
    private val globalCorsConfigurations: CorsConfigurations?,
    private val appLoginProperties: AppLoginProperties,
    private val cookieService: CookieService,
    private val authorizedClientRepository: OAuth2AuthorizedClientRepository,
    private val securityContextRepository: SecurityContextRepository,
    private val clientRegistrationRepository: ClientRegistrationRepository,
    private val organizationCorsConfigurationSource: OrganizationCorsConfigurationSource,
) : WebSecurityConfigurerAdapter() {

    @Suppress("LongMethod")
    override fun configure(http: HttpSecurity) {
        val cookieRequestCache = CookieRequestCache(cookieService)
        val oAuth2AuthorizedClientRepository = authorizedClientRepository
        val hostBasedAuthEntryPoint = HostBasedAuthenticationEntryPoint(cookieRequestCache)
        val logoutHandler = CompositeLogoutHandler(
            SecurityContextClearingLogoutHandler(securityContextRepository),
            LogoutHandler { request, response, authentication ->
                oAuth2AuthorizedClientRepository.removeAuthorizedClient(
                    request.serverName, authentication, request, response
                )
            }
        )

        (http.securityContext { it.securityContextRepository(securityContextRepository) }) {
            securityMatcher(
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
            oauth2ResourceServer {
                authenticationManagerResolver =
                    BearerTokenAuthenticationManagerResolver(authenticationStoreClient.`object`)
            }
            oauth2Login {
                authorizationEndpoint {
                    authorizationRequestRepository = CookieAuthorizationRequestRepository(cookieService)
                }
                authorizedClientRepository = oAuth2AuthorizedClientRepository
                authenticationSuccessHandler =
                    CookieAndSavedRequestAwareAuthenticationSuccessHandler(securityContextRepository).apply {
                        setRequestCache(cookieRequestCache)
                    }
                authenticationFailureHandler = OAuth2FailureHandler()
            }
            exceptionHandling {
                authenticationEntryPoint = hostBasedAuthEntryPoint
            }
            authorizeRequests {
                authorize(anyRequest, authenticated)
            }
            requestCache {
                requestCache = cookieRequestCache
            }
            csrf { disable() }
            headers {
                contentTypeOptions {}
                cacheControl {}
                httpStrictTransportSecurity {}
            }
            logout {
                logoutSuccessHandler =
                    OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository).apply {
                        setPostLogoutRedirectUri("{baseUrl}")
                    }
                addLogoutHandler(logoutHandler)
                logoutRequestMatcher = AntPathRequestMatcher("/logout", "GET")
            }
            addFilterBefore(PostLogoutNotAllowedFilter(), LogoutFilter::class.java)
            addFilterBefore(
                ResponseStatusExceptionHandlingFilter(),
                BearerTokenAuthenticationFilter::class.java,
            )
            addFilterAfter(
                UserContextFilter(
                    authenticationStoreClient.`object`,
                    hostBasedAuthEntryPoint,
                    logoutHandler,
                    userContextHolder.`object`
                ),
                ExceptionTranslationFilter::class.java
            )
            oauth2Client {}
            cors {
                this.configurationSource = CompositeCorsConfigurationSource(
                    UrlBasedCorsConfigurationSource().apply {
                        globalCorsConfigurations?.configurations?.forEach { (pattern, config) ->
                            registerCorsConfiguration(pattern, config)
                        }
                    },
                    organizationCorsConfigurationSource,
                    appLoginProperties.allowRedirect.toString()
                )
            }
        }
    }
}
