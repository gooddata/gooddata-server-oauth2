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

import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.http.HttpHeaders
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.server.ServerWebExchange

/**
 * CORS configuration source which provides configuration based organization configuration .
 * @param[authenticationStoreClient] client for retrieving organization based identity objects from persistent storage
 */
class OrganizationCorsConfigurationSource(private val authenticationStoreClient: AuthenticationStoreClient) {

    private val logger = KotlinLogging.logger {}

    @Suppress("TooGenericExceptionCaught")
    fun getOrganizationCorsConfiguration(exchange: ServerWebExchange) =
        exchange.getOrganizationFromAttributes().allowedOrigins?.toCorsConfiguration()
}

/**
 * Convert allowed origins list to CORS configuration allowing all methods, all headers and credentials.
 * @receiver allowed origins hosts
 */
private fun List<String>.toCorsConfiguration() = CorsConfiguration().apply {
    allowCredentials = true
    allowedMethods = listOf(CorsConfiguration.ALL)
    allowedHeaders = listOf(CorsConfiguration.ALL)
    exposedHeaders = listOf(HttpHeaders.CONTENT_DISPOSITION)
    val (originPatterns, origins) = this@toCorsConfiguration.partition(String::isWildcardOrigin)
    allowedOrigins = origins.takeIf(List<String>::isNotEmpty)
    allowedOriginPatterns = originPatterns.takeIf(List<String>::isNotEmpty)
}

/**
 * Check if the allowed origin is a wildcard. We simply check for the presence of '*' without any validation.
 * @receiver allowed origin host
 */
private fun String.isWildcardOrigin() = contains('*')

/**
 * Convert allowed origin host to CORS configuration allowing all methods, all headers and credentials.
 * @receiver allowed origin host
 */
fun String.toCorsConfiguration() = listOf(this).toCorsConfiguration()
