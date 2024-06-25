/*
 * Copyright 2024 GoodData Corporation
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

import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler
import reactor.core.publisher.Mono
import java.net.URI

/**
 * Extends functionality of [OidcClientInitiatedServerLogoutSuccessHandler]. Allows to set the post logout redirect URI
 * based on the `returnTo` query parameter from the request.
 *
 * @param [clientRegistrationRepository] the repository for client registrations
 * @param [postLogoutRedirectUri] the default post logout redirect URI,
 * see [OidcClientInitiatedServerLogoutSuccessHandler.setPostLogoutRedirectUri]
 * @param [defaultLogoutSuccessUrl] the default logout success URL,
 * see [OidcClientInitiatedServerLogoutSuccessHandler.setLogoutSuccessUrl]
 *
 * @see [OidcClientInitiatedServerLogoutSuccessHandler]
 */
class QueryParamOidcClientInitiatedServerLogoutSuccessHandler(
    private val clientRegistrationRepository: ReactiveClientRegistrationRepository,
    private val postLogoutRedirectUri: String,
    private val defaultLogoutSuccessUrl: String,
) : ServerLogoutSuccessHandler {

    override fun onLogoutSuccess(exchange: WebFilterExchange, authentication: Authentication): Mono<Void> =
        OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository)
            .apply {
                setPostLogoutRedirectUri(postLogoutRedirectUri)
                setLogoutSuccessUrl(
                    // workaround for STL-458: use URL from 'returnTo' query parameter if provided,
                    // otherwise use default URL
                    URI.create(exchange.returnToQueryParam() ?: defaultLogoutSuccessUrl)
                )
            }
            .onLogoutSuccess(exchange, authentication)
}
