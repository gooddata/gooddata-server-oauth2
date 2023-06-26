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

import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono

sealed class AuthenticationProcessor<in authenticationToken : AbstractAuthenticationToken>(
    private val reactorUserContextProvider: ReactorUserContextProvider
) {

    abstract fun authenticate(
        authenticationToken: authenticationToken,
        exchange: ServerWebExchange,
        chain: WebFilterChain
    ): Mono<Void>

    protected fun <T> withUserContext(
        organization: Organization,
        user: User,
        name: String?,
        monoProvider: () -> Mono<T>,
    ): Mono<T> = monoProvider().contextWrite(reactorUserContextProvider.getContextView(organization.id, user.id, name))
}
