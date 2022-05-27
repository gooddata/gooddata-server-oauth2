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

import com.gooddata.oauth2.server.common.AuthenticationStoreClient
import com.gooddata.oauth2.server.common.CachingProperties
import com.gooddata.oauth2.server.common.CookieServiceProperties
import com.gooddata.oauth2.server.common.HostBasedClientRegistrationRepositoryProperties
import com.gooddata.oauth2.server.common.CookieSerializer
import com.gooddata.oauth2.server.common.ClientRegistrationBuilderCache
import com.gooddata.oauth2.server.common.CaffeineClientRegistrationCache
import com.gooddata.oauth2.server.common.CaffeineJwkCache
import com.gooddata.oauth2.server.common.JwkCache
import com.gooddata.oauth2.server.common.OrganizationCorsConfigurationSource
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.jwt.JwtDecoderFactory
import org.springframework.security.web.context.SecurityContextRepository
import javax.servlet.Filter

@Configuration
@EnableConfigurationProperties(
    CookieServiceProperties::class,
    HostBasedClientRegistrationRepositoryProperties::class,
    CachingProperties::class
)
@ConditionalOnClass(Filter::class)
@Import(OAuth2SecurityConfiguration::class)
class OAuth2AutoConfiguration {
    /**
     * This cannot be on top-level configuration class as annotation would be processed even though configuration
     * would be disabled by conditionals.
     */
    @EnableWebSecurity
    class EnabledSecurity

    @Bean
    fun cookieSerializer(
        authenticationStoreClient: ObjectProvider<AuthenticationStoreClient>,
        cookieServiceProperties: CookieServiceProperties,
    ) = CookieSerializer(cookieServiceProperties, authenticationStoreClient.`object`)

    @Bean
    fun cookieService(cookieServiceProperties: CookieServiceProperties, cookieSerializer: CookieSerializer) =
        CookieService(cookieServiceProperties, cookieSerializer)

    @Bean
    fun authorizedClientRepository(
        cookieService: CookieService,
        clientRegistrationRepository: ClientRegistrationRepository,
    ): OAuth2AuthorizedClientRepository =
        CookieOAuth2AuthorizedClientRepository(clientRegistrationRepository, cookieService)

    @Bean
    fun clientRegistrationRepository(
        authenticationStoreClient: ObjectProvider<AuthenticationStoreClient>,
        hostBasedClientRegistrationRepositoryProperties: HostBasedClientRegistrationRepositoryProperties,
        cachingProperties: CachingProperties,
    ): ClientRegistrationRepository =
        HostBasedClientRegistrationRepository(
            authenticationStoreClient.`object`,
            hostBasedClientRegistrationRepositoryProperties,
            clientRegistrationCache(cachingProperties)
        )

    @ConditionalOnMissingBean(ClientRegistrationBuilderCache::class)
    @Bean
    fun clientRegistrationCache(cachingProperties: CachingProperties): ClientRegistrationBuilderCache =
        CaffeineClientRegistrationCache(
            cachingProperties.clientRegistrationMaxSize,
            cachingProperties.clientRegistrationExpireAfterWriteMinutes
        )

    @Bean
    fun securityContextRepository(
        jwtDecoderFactory: JwtDecoderFactory<ClientRegistration>,
        cookieService: CookieService,
        clientRegistrationRepository: ClientRegistrationRepository,
    ): SecurityContextRepository =
        CookieSecurityContextRepository(clientRegistrationRepository, cookieService, jwtDecoderFactory)

    @Bean
    fun jwtDecoderFactory(jwkCache: JwkCache): JwtDecoderFactory<ClientRegistration> = JwkCachingDecoderFactory(
        jwkCache
    )

    @ConditionalOnMissingBean(JwkCache::class)
    @Bean
    fun jwkCache(cachingProperties: CachingProperties) =
        CaffeineJwkCache(cachingProperties.jwkMaxSize, cachingProperties.jwkExpireAfterWriteMinutes)

    @Bean
    fun organizationCorsConfigurationSource(
        authenticationStoreClient: AuthenticationStoreClient
    ) = OrganizationCorsConfigurationSource(authenticationStoreClient)
}
