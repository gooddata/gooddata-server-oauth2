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

/**
 * Interface for processing call context headers from internal service-to-service calls.
 *
 * Implementations should parse the call context header and extract authentication
 * information that has already been validated by an upstream service.
 *
 * The implementation should be provided by the application using this library.
 */
interface CallContextHeaderProcessor {

    /**
     * The name of the HTTP header to use for call context authentication.
     *
     * @return The HTTP header name (e.g., "X-Custom-Context-Header")
     */
    fun getHeaderName(): String

    /**
     * Parses the call context header value and returns authentication details.
     *
     * @param headerValue The header value (typically Base64-encoded)
     * @return [CallContextAuth] containing authentication information, or null if the header has no user or
     * organization information (which signals that CallContext authentication should be skipped)
     */
    fun parseCallContextHeader(headerValue: String): CallContextAuth?
}

/**
 * Authentication details extracted from a call context header.
 *
 * @property organizationId The organization ID
 * @property userId The user ID
 * @property authMethod The authentication method (e.g., "API_TOKEN", "OIDC", "JWT")
 * @property tokenId The token ID if applicable
 */
data class CallContextAuth(
    val organizationId: String,
    val userId: String,
    val authMethod: String,
    val tokenId: String? = null
)
