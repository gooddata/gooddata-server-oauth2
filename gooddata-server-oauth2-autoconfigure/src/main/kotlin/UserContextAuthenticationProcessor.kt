/*
 * Copyright 2023 GoodData Corporation
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

import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilterChain

/**
 *  If `SecurityContext` contains [UserContextAuthenticationToken] the [UserContextAuthenticationProcessor] handles the
 *  authentication by extracting the security context and creating user context according to its content.
 */
class UserContextAuthenticationProcessor(
    reactorUserContextProvider: ReactorUserContextProvider
) : AuthenticationProcessor<UserContextAuthenticationToken>(reactorUserContextProvider) {

    override fun authenticate(
        authenticationToken: UserContextAuthenticationToken,
        exchange: ServerWebExchange,
        chain: WebFilterChain
    ) = with(authenticationToken) {
        withUserContext(organization, user, null) {
            chain.filter(exchange)
        }
    }
}
