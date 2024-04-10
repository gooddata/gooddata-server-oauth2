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

import reactor.core.publisher.Mono
import reactor.util.context.ContextView

/**
 * Interface defining contract for storing and accessing current authenticated user context. Client is responsible for
 * the creation of any data structure it feels appropriate.
 *
 * Created context is passed as a coroutine context to subsequent coroutine-based filter calls.
 *
 * This interface will probably be removed in future implementations.
 *
 * @see ReactorUserContextProvider
 */
interface UserContextHolder<UserContextT : AuthenticationUserContext> {

    /**
     * Gets currently available authenticated user context.
     */
    fun getContext(): Mono<UserContextT>
}

/**
 * Interface defining contract for providing current authenticated user context as a reactor's [ContextView]. Client
 * is responsible for the creation of any data structure it feels appropriate.
 *
 * This interface is tightly connected to [UserContextHolder] interface, so the client should implement both of them
 * in the same way.
 *
 * @see UserContextHolder
 */
fun interface ReactorUserContextProvider {

    /**
     * Provides the [ContextView] with a client defined data structure which contains the user's context.
     *
     * @param[organizationId] the user's organization
     * @param[userId] the ID of the user
     * @param[userName] the name of the user
     * @param[tokenId] the ID of the ApiToken or null for other tokens
     * @return [ContextView] containing the user's context
     */
    fun getContextView(organizationId: String, userId: String, userName: String?, tokenId: String?): ContextView
}

/**
 * `AuthenticationUserContext` defines minimal contract user context needs to implement so authentication library needs
 * for can process it.
 */
interface AuthenticationUserContext {
    /**
     * Organization ID authenticated user belongs to.
     */
    val organizationId: String

    /**
     * Authenticated user's ID.
     */
    val userId: String

    /**
     * ID of the apiToken
     */
    val tokenId: String?
}
