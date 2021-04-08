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
package com.gooddata.oauth2.server.reactive

import com.gooddata.oauth2.server.common.AuthenticationStoreClient
import kotlinx.coroutines.reactor.mono
import org.springframework.security.core.Authentication
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler
import reactor.core.publisher.Mono

/**
 * [ServerLogoutHandler] that sets `logoutAll` property on `User` object in persistent storage. All applications must
 * read this property to verify whether used ID tokens can be accepted or not.
 */
class LogoutAllServerLogoutHandler(
    private val client: AuthenticationStoreClient,
    private val userContextHolder: UserContextHolder<*>,
) : ServerLogoutHandler {

    override fun logout(exchange: WebFilterExchange, authentication: Authentication): Mono<Void> =
        mono {
            userContextHolder.getContext()
                ?.let {
                    client.logoutAll(it.userId, it.organizationId)
                }
        }.then()
}
