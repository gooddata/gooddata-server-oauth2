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

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.converter.FormHttpMessageConverter
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient
import org.springframework.security.oauth2.client.endpoint.DefaultClientCredentialsTokenResponseClient
import org.springframework.security.oauth2.client.endpoint.DefaultPasswordTokenResponseClient
import org.springframework.security.oauth2.client.endpoint.DefaultRefreshTokenTokenResponseClient
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest
import org.springframework.security.oauth2.client.endpoint.OAuth2PasswordGrantRequest
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.web.client.RestOperations
import org.springframework.web.client.RestTemplate


/**
 * Configuration for all clients for requesting data from OAuth2 server.
 */
@Configuration
class OAuth2ClientsConfiguration {

    @Bean
    fun oauth2UserService(
        oauth2ClientRestOperations: RestOperations,
    ): OAuth2UserService<OAuth2UserRequest, OAuth2User> =
        DefaultOAuth2UserService().apply {
            setRestOperations(oauth2ClientRestOperations)
        }

    @Bean
    fun oidcUserService(
        oauth2UserService: OAuth2UserService<OAuth2UserRequest, OAuth2User>,
    ): OAuth2UserService<OidcUserRequest, OidcUser> =
        OidcUserService().apply {
            setOauth2UserService(oauth2UserService)
        }

    @Bean
    fun authorizationCodeTokenResponseClient(
        oauth2ClientRestOperations: RestOperations,
    ): OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> =
        DefaultAuthorizationCodeTokenResponseClient().apply {
            setRestOperations(oauth2ClientRestOperations)
        }

    @Bean
    fun refreshTokenTokenResponseClient(
        oauth2ClientRestOperations: RestOperations
    ): OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> =
        DefaultRefreshTokenTokenResponseClient().apply {
            setRestOperations(oauth2ClientRestOperations)
        }

    @Bean
    fun clientCredentialsTokenResponseClient(
        oauth2ClientRestOperations: RestOperations
    ): OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> =
        DefaultClientCredentialsTokenResponseClient().apply {
            setRestOperations(oauth2ClientRestOperations)
        }

    @Bean
    fun passwordTokenResponseClient(
        oauth2ClientRestOperations: RestOperations,
    ): OAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> =
        DefaultPasswordTokenResponseClient().apply {
            setRestOperations(oauth2ClientRestOperations)
        }
}
