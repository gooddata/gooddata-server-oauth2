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

import com.nimbusds.jose.jwk.JWK
import java.time.Instant
import java.time.LocalDateTime
import org.springframework.http.HttpStatus
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException
import org.springframework.web.server.ResponseStatusException

/**
 * `AuthenticationStoreClient` defines methods for retrieving identity objects from persistent storage.
 */
@SuppressWarnings("TooManyFunctions")
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
     *
     * Retrieves [User] that belongs to given `organizationId`
     *
     * @param organizationId ID of the organization that the user belongs to
     * @param token API token to be searched
     * @return `User` corresponding to `hostname`
     * TODO exception should be handled directly in the library
     * @throws InvalidBearerTokenException in case no [User] is found
     */
    suspend fun getUserByApiToken(organizationId: String, token: String): User

    /**
     *
     * Retrieves [User] that belongs to given `organizationId`
     *
     * @param organizationId ID of the organization that the user belongs to
     * @param userId id of the user to be searched
     * @return `User` corresponding to userId
     * TODO should an exception be thrown if the user is not found?
     */
    suspend fun getUserById(organizationId: String, userId: String): User?

    /**
     * Creates [User] that belongs to given `organizationId`
     * @param organizationId ID of the organization that the user belongs to
     * @param authenticationId ID identifying the user in OIDC provider
     * @param firstName first name of the user
     * @param lastName last name of the user
     * @param email email of the user
     * @param userGroups list of user groups where the user belongs to
     * @return created [User]
     */
    @SuppressWarnings("LongParameterList")
    suspend fun createUser(
        organizationId: String,
        authenticationId: String,
        firstName: String,
        lastName: String,
        email: String,
        userGroups: List<String>
    ): User

    /**
     * Patches [User] in the given `organizationId`
     * @return updated [User]
     */
    suspend fun patchUser(organizationId: String, user: User): User

    /**
     *
     * Retrieves [List<JWK>] that belongs to given `organizationId`
     *
     * @param organizationId ID of the organization that the JWKs belongs to
     * @return list of JWKs corresponding to organizationId
     */
    suspend fun getJwks(organizationId: String): List<JWK>

    /**
     * Checks whether JWT, that belongs to organization `organizationId` and user `userId` specified by `jwtHash`
     * (optionally also by `jwtId` for faster processing) is valid
     *
     * @param organizationId ID of the organization that the JWTs belongs to
     * @param userId ID of the user that the JWTs belongs to
     * @param jwtHash md5 hash of the JWT token
     * @param jwtId ID of the JWT (optional)
     * @return true if the JWT is valid, false otherwise
     */
    suspend fun isValidJwt(organizationId: String, userId: String, jwtHash: String, jwtId: String?): Boolean

    /**
     * Invalidates JWT, that belongs to organization `organizationId` and user `userId` specified by `jwtHash`
     * (optionally also by `jwtId` for faster processing) is valid
     *
     * @param organizationId ID of the organization that the JWTs belongs to
     * @param userId ID of the user that the JWTs belongs to
     * @param jwtHash md5 hash of the JWT token
     * @param jwtId ID of the JWT (optional)
     * @param validTo UTC time of JWT expiration
     */
    suspend fun invalidateJwt(
        organizationId: String,
        userId: String,
        jwtHash: String,
        jwtId: String?,
        validTo: LocalDateTime
    )

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

/**
 * Represents the single organization stored in the persistent storage and having its hostname and own specific OAuth
 * settings.
 *
 * @property id the ID of this organization within the persistent storage
 * @property oauthIssuerLocation the location URL of the OAuth issuer
 * @property oauthClientId the identifier of the application registered in the OAuth issuer
 * @property oauthClientSecret the secret of the application registered in the OAuth issuer
 * @property allowedOrigins the list of hosts (origins) for which
 * * the successful application login is allowed to redirect
 * * the CORS requests are allowed
 * @property oauthIssuerId the ID of the OAuth issuer. This value is used as suffix for OAuth callback (redirect) URL.
 * If not defined (`null` value), the standard callback URL is used. Defaults to `null`.
 * * callback URL with this value: `<hostUrl>/<action>/oauth2/code/<oauthIssuerId>`
 * * standard callback URL: `<hostUrl>/<action>/oauth2/code/<registrationId>` (see
 * [org.springframework.security.oauth2.client.registration.ClientRegistration])
 * @property oauthSubjectIdClaim name of the claim in ID token that will be used for finding the user in organization.
 * Defaults to `null` and it means that `sub` claim will be used.
 * @property jitEnabled the switch for enabling/disabling of the JIT provisioning
 *
 * @see AuthenticationStoreClient
 */
data class Organization(
    val id: String,
    val oauthIssuerLocation: String? = null,
    val oauthClientId: String? = null,
    val oauthClientSecret: String? = null,
    val allowedOrigins: List<String>? = null,
    val oauthIssuerId: String? = null,
    val oauthSubjectIdClaim: String? = null,
    val jitEnabled: Boolean? = null,
)

/**
 * Represents authenticated end-user (principal) stored in the persistent storage.
 *
 * @property id the ID of this end-user within the persistent storage
 * @property lastLogoutAllTimestamp timestamp, when this end-user hit "Logout From All Sessions" last time
 * @property id of ApiToken, if found by [BearerTokenAuthenticationToken], null for other cases
 *
 * @see AuthenticationStoreClient
 */
data class User(
    val id: String,
    val lastLogoutAllTimestamp: Instant? = null,
    val usedTokenId: String? = null,
    val name: String? = null,
    var firstname: String? = null,
    var lastname: String? = null,
    var email: String? = null,
    var userGroups: List<String>? = null,
)
