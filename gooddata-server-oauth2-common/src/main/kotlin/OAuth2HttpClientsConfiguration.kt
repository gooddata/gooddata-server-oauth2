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
package com.gooddata.oauth2.server.common

import org.springframework.boot.web.client.RestTemplateBuilder
import org.springframework.context.annotation.Bean
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory
import org.springframework.http.converter.FormHttpMessageConverter
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter
import org.springframework.web.client.RestOperations
import org.springframework.web.client.RestTemplate

/**
 * Basic configuration for any HTTP client accessing OAuth2 server endpoints.
 */
class OAuth2HttpClientsConfiguration {

    @Bean
    fun oauth2ClientRestOperations(
        restTemplateBuilder: RestTemplateBuilder
    ): RestOperations = RestTemplate().apply {
        messageConverters = listOf(
            FormHttpMessageConverter(),
            OAuth2AccessTokenResponseHttpMessageConverter(),
            MappingJackson2HttpMessageConverter(),
        )
        requestFactory = HttpComponentsClientHttpRequestFactory().apply {
            TODO()
        }
        errorHandler = OAuth2ErrorResponseErrorHandler()
    }
}
