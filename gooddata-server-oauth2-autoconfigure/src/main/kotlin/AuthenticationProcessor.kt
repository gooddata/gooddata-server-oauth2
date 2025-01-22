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

/**
 * AuthenticationProcessor defines common authentication method for all authentication processors.
 *
 * @param authenticationToken specifies the type of authentication for which is the processor responsible
 */
sealed class AuthenticationProcessor<in authenticationToken : AbstractAuthenticationToken>(
    private val reactorUserContextProvider: ReactorUserContextProvider
) {

    /**
     * Authenticates user based on the provided [authenticationToken]
     *
     * @param authenticationToken Token to be used for user authentication
     * @param exchange Contract for an HTTP request-response interaction
     * @param chain Contract to allow a WebFilter to delegate to the next in the chain.
     */
    abstract fun authenticate(
        authenticationToken: authenticationToken,
        exchange: ServerWebExchange,
        chain: WebFilterChain
    ): Mono<Void>

    @SuppressWarnings("LongParameterList")
    protected fun <T> withUserContext(
        organization: Organization,
        user: User,
        name: String?,
        authMethod: AuthMethod?,
        authId: String? = null,
        monoProvider: () -> Mono<T>,
    ): Mono<T> = monoProvider().contextWrite(
        when (authMethod) {
            AuthMethod.OIDC, AuthMethod.JWT -> reactorUserContextProvider.getContextView(
                organization.id,
                user.id,
                name,
                authId,
                authMethod
            )
            else -> reactorUserContextProvider.getContextView(
                organization.id,
                user.id,
                name,
                user.usedTokenId,
                authMethod
            )
        }
    )
}
