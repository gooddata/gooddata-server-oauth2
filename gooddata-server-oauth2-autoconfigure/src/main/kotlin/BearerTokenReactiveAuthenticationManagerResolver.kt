/*
 * Copyright 2021 GoodData Corporation
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

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.reactor.mono
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

/**
 * [ReactiveAuthenticationManagerResolver] that is able to authenticate bearer tokens.
 */
class BearerTokenReactiveAuthenticationManagerResolver(
    private val client: AuthenticationStoreClient,
) : ReactiveAuthenticationManagerResolver<ServerWebExchange> {

    override fun resolve(exchange: ServerWebExchange): Mono<ReactiveAuthenticationManager> =
        mono(Dispatchers.Unconfined) {
            ReactiveAuthenticationManager { authentication ->
                mono(Dispatchers.Unconfined) {
                    (authentication as? BearerTokenAuthenticationToken)?.let { authenticationToken ->
                        userContextAuthenticationToken(client, exchange.request.uri.host, authenticationToken)
                    }
                }
            }
        }
}
