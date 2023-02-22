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

import io.netty.channel.ChannelOption
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.client.SimpleClientHttpRequestFactory
import org.springframework.http.client.reactive.ReactorClientHttpConnector
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveRefreshTokenTokenResponseClient
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.web.client.RestTemplate
import org.springframework.web.reactive.function.client.WebClient
import reactor.netty.http.client.HttpClient
import reactor.netty.resources.ConnectionProvider
import reactor.netty.resources.ConnectionProvider.DEFAULT_POOL_ACQUIRE_TIMEOUT
import java.time.Duration

private const val DEFAULT_MAX_CONNECTIONS = 500
private const val CUSTOM_CONNECTION_PROVIDER_NAME = "gdc-connection-provider"

/**
 * Configuration of clients communicating with Oauth2 auth server HTTP endpoints
 */
@EnableConfigurationProperties(HttpProperties::class)
@Configuration
class ReactiveCommunicationClientsConfiguration(private val httpProperties: HttpProperties) {

    @Bean
    fun customWebClient(): WebClient {
        val httpClient = HttpClient.create(connectionProvider())
            .responseTimeout(Duration.ofMillis(httpProperties.readTimeoutMillis.toLong()))
            .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, httpProperties.connectTimeoutMillis)
        return WebClient.builder()
            .clientConnector(ReactorClientHttpConnector(httpClient))
            .build()
    }

    /**
     * taken from reactor.netty.resources.ConnectionProvider.create(java.lang.String, int)
     */
    private fun connectionProvider(): ConnectionProvider {
        return ConnectionProvider.builder(CUSTOM_CONNECTION_PROVIDER_NAME)
            .maxConnections(DEFAULT_MAX_CONNECTIONS)
            .pendingAcquireTimeout(Duration.ofMillis(DEFAULT_POOL_ACQUIRE_TIMEOUT))
            // we don't want netty to retry with another connection from the pool when the idle timout is reached
            // see https://github.com/reactor/reactor-netty/issues/564#issuecomment-576244256
            .lifo()
            .maxIdleTime(Duration.ofMillis(httpProperties.connectionIdleTimeoutMillis.toLong()))
            .build()
    }

    /**
     * A [RestTemplate] with custom readTimeout and connectTimeout. Needed for [SimpleRemoteJwkSource]
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
    fun authCodeAccessTokenResponseClient(
        webClient: WebClient,
    ): ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> =
        WebClientReactiveAuthorizationCodeTokenResponseClient().apply {
            setWebClient(webClient)
            setBodyExtractor(SafeOAuth2AccessTokenResponseBodyExtractor())
        }

    @Bean
    fun oauth2UserService(webClient: WebClient): ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> =
        DefaultReactiveOAuth2UserService().apply {
            setWebClient(webClient)
        }

    @Bean
    fun oidcUserService(
        userService: ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User>,
    ): ReactiveOAuth2UserService<OidcUserRequest, OidcUser> =
        OidcReactiveOAuth2UserService().apply {
            setOauth2UserService(userService)
        }

    @Bean
    fun refreshTokenResponseClient(
        webClient: WebClient,
    ): ReactiveOAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> =
        WebClientReactiveRefreshTokenTokenResponseClient().apply {
            setWebClient(webClient)
            setBodyExtractor(SafeOAuth2AccessTokenResponseBodyExtractor())
        }
}
