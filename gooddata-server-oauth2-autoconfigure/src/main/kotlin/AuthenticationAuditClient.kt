/*
 * Copyright 2025 GoodData Corporation
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

/**
 * Client interface for recording authentication audit events.
 */
interface AuthenticationAuditClient {
    /**
     * Records a successful login event.
     *
     * @param orgId The organization ID
     * @param userId The user ID
     * @param source The source of the login
     * @param sessionContextType The method of authentication
     * @param sessionContextIdentifier The session context identifier
     * @return Mono<Void> that completes when the event has been recorded
     */
    @Suppress("LongParameterList")
    fun recordLoginSuccess(
        orgId: String,
        userId: String,
        source: String?,
        sessionContextType: AuthMethod,
        sessionContextIdentifier: String?,
    ): Mono<Void>

    /**
     * Records a failed login event.
     *
     * @param orgId The organization ID
     * @param userId The user ID
     * @param source The source of the login
     * @param sessionContextType The method of authentication
     * @param sessionContextIdentifier The session context identifier
     * @param errorCode Optional error code (null by default)
     * @param details Optional map of additional details to record (null by default)
     * @return Mono<Void> that completes when the event has been recorded
     */
    @Suppress("LongParameterList")
    fun recordLoginFailure(
        orgId: String,
        userId: String,
        source: String?,
        sessionContextType: AuthMethod,
        sessionContextIdentifier: String?,
        errorCode: String? = null,
        details: Map<String, Any>? = null
    ): Mono<Void>

    /**
     * Records a logout event.
     *
     * @param orgId The organization ID
     * @param userId The user ID
     * @param source The source of the logout
     * @param sessionContextType The method of authentication
     * @param sessionContextIdentifier The session context identifier
     * @param errorCode Optional error code (null by default)
     * @return Mono<Void> that completes when the event has been recorded
     */
    @Suppress("LongParameterList")
    fun recordLogout(
        orgId: String,
        userId: String,
        source: String?,
        sessionContextType: AuthMethod,
        sessionContextIdentifier: String?,
        errorCode: String? = null
    ): Mono<Void>
}
