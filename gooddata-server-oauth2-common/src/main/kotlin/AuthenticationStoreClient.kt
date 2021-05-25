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
package com.gooddata.oauth2.server.common

import org.springframework.http.HttpStatus
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException
import org.springframework.web.server.ResponseStatusException
import java.time.Instant

/**
 * `AuthenticationStoreClient` defines methods for retrieving identity objects from persistent storage.
 */
interface AuthenticationStoreClient {

    /**
     * Retrieves [Organization] that corresponds to provided `hostname`. [ResponseStatusException]
     * with [HttpStatus.NOT_FOUND] status code is thrown in case no [Organization] can be found.
     *
     * @param hostname of the organization
     * @return `Organization` corresponding to `hostname`
     * @throws ResponseStatusException in case `Organization` is not found
     */
    suspend fun getOrganizationByHostname(hostname: String): Organization

    /**
     * Retrieves [User] that corresponds to provided `organizationId` and `authenticationId` retrieved from
     * OIDC ID token.
     *
     * Returns `null` in case no [User] can be found.
     *
     * @param organizationId ID identifying the organization
     * @param authenticationId ID identifying the user in OIDC provider
     * @return found [User] or `null` in case no [User] is found
     */
    suspend fun getUserByAuthenticationId(organizationId: String, authenticationId: String): User?

    /**
     * Retrieves [User] that belongs to given `organizationId`
     *
     * @param organizationId ID of the organization that the user belongs to
     * @param token API token to be searched
     * @return `User` corresponding to `hostname`
     * @throws InvalidBearerTokenException in case no [User] is found
     */
    suspend fun getUserByApiToken(organizationId: String, token: String): User

    /**
     * Marks the [User] belonging to the [Organization] for global logout. Any OIDC tokens which were issued before that
     * actions are to be considered as expired.
     *
     * @param userId ID identifying the user
     * @param organizationId ID identifying the organization
     */
    suspend fun logoutAll(userId: String, organizationId: String)

    /**
     * Retrieve [CookieSecurityProperties] for given organization.
     *
     * @param organizationId ID identifying the organization
     * @return [CookieSecurityProperties] for given organization
     */
    suspend fun getCookieSecurityProperties(organizationId: String): CookieSecurityProperties
}

data class Organization(
    val id: String,
    val oauthIssuerLocation: String? = null,
    val oauthClientId: String? = null,
    val oauthClientSecret: String? = null,
)

data class User(
    val id: String,
    val lastLogoutAllTimestamp: Instant? = null,
)
