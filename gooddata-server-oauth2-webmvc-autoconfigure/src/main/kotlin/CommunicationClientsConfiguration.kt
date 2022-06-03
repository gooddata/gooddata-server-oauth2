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

import com.gooddata.oauth2.server.common.HttpProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.client.SimpleClientHttpRequestFactory
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.web.client.RestTemplate

/**
 * Configuration of clients communicating with Oauth2 auth server HTTP endpoints
 */
@EnableConfigurationProperties(HttpProperties::class)
@Configuration
class CommunicationClientsConfiguration(private val httpProperties: HttpProperties) {

    /**
     * A [RestTemplate] with custom readTimeout and connectTimeout.
     */
    @Bean
    fun customRestTemplate(): RestTemplate {
        val restTemplate = RestTemplate()
        restTemplate.messageConverters.add(OAuth2AccessTokenResponseHttpMessageConverter())
        restTemplate.errorHandler = OAuth2ErrorResponseErrorHandler()
        restTemplate.requestFactory = SimpleClientHttpRequestFactory().apply {
            setConnectTimeout(httpProperties.connectTimeoutMillis)
            setReadTimeout(httpProperties.readTimeoutMillis)
        }
        return restTemplate
    }

    @Bean
    fun oauth2UserService(restTemplate: RestTemplate): OAuth2UserService<OAuth2UserRequest, OAuth2User> {
        val userService = DefaultOAuth2UserService()
        userService.setRestOperations(restTemplate)
        return userService
    }

    @Bean
    fun oidcUserService(
        oauth2UserService: OAuth2UserService<OAuth2UserRequest, OAuth2User>
    ): OAuth2UserService<OidcUserRequest, OidcUser> {
        val userService = OidcUserService()
        userService.setOauth2UserService(oauth2UserService)
        return userService
    }

    @Bean
    fun authCodeAccessTokenResponseClient(
        restTemplate: RestTemplate
    ): OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {
        val tokenResponseClient = DefaultAuthorizationCodeTokenResponseClient()
        tokenResponseClient.setRestOperations(restTemplate)
        return tokenResponseClient
    }
}
