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

import com.gooddata.oauth2.server.common.OrganizationCorsConfigurationSource
import com.gooddata.oauth2.server.common.toCorsConfiguration
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.reactive.CorsConfigurationSource
import org.springframework.web.server.ServerWebExchange

/**
 * Configuration source which tries to find CORS settings in global configuration. If none is found, then tries
 * organization settings.
 * @param[corsConfigurationSource] CORS configuration source for whole application
 * @param[organizationCorsConfigurationSource] CORS configuration source for organization
 * @param[allowRedirect] host which is allowed to redirect to (it also has to be added to CORS)
 */
class CompositeCorsConfigurationSource(
    private val corsConfigurationSource: CorsConfigurationSource,
    private val organizationCorsConfigurationSource: OrganizationCorsConfigurationSource,
    private val allowRedirect: String
) : CorsConfigurationSource {

    override fun getCorsConfiguration(exchange: ServerWebExchange): CorsConfiguration? =
        corsConfigurationSource.getCorsConfiguration(exchange)
            ?: getOrganizationConfiguration(exchange) ?: allowRedirect.toCorsConfiguration()

    private fun getOrganizationConfiguration(
        exchange: ServerWebExchange
    ): CorsConfiguration? = exchange.request.uri.host?.let { host ->
        organizationCorsConfigurationSource.getOrganizationCorsConfiguration(host)
    }
}
