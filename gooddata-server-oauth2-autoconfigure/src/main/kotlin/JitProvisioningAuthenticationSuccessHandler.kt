/*
 * Copyright 2024 GoodData Corporation
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

import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.http.HttpStatus
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.oidc.StandardClaimNames.EMAIL
import org.springframework.security.oauth2.core.oidc.StandardClaimNames.FAMILY_NAME
import org.springframework.security.oauth2.core.oidc.StandardClaimNames.GIVEN_NAME
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import org.springframework.web.server.ResponseStatusException
import reactor.core.publisher.Mono
import reactor.kotlin.core.publisher.switchIfEmpty

class JitProvisioningAuthenticationSuccessHandler(
    private val client: AuthenticationStoreClient
) : ServerAuthenticationSuccessHandler {

    private val logger = KotlinLogging.logger {}

    override fun onAuthenticationSuccess(
        webFilterExchange: WebFilterExchange?,
        authentication: Authentication?
    ): Mono<Void> = Mono.justOrEmpty(authentication)
        .cast(OAuth2AuthenticationToken::class.java)
        .flatMap { provisionUser(it, webFilterExchange) }
        .then()

    private fun provisionUser(
        authenticationToken: OAuth2AuthenticationToken,
        webFilterExchange: WebFilterExchange?,
    ): Mono<User> {
        return client.getOrganizationByHostname(
            webFilterExchange?.exchange?.request?.uri?.host ?: ""
        ).flatMap { organization ->
            if (organization.jitEnabled == true) {
                provisionUser(authenticationToken, organization)
            } else {
                logMessage("JIT provisioning disabled, skipping", "finished", "")
                Mono.empty()
            }
        }
    }

    private fun provisionUser(
        authenticationToken: OAuth2AuthenticationToken,
        organization: Organization
    ): Mono<User> {
        checkMandatoryClaims(authenticationToken, organization.id)
        logMessage("Initiating JIT provisioning", "started", organization.id)
        val subClaim = authenticationToken.getClaim(organization.oauthSubjectIdClaim)
        val firstnameClaim = authenticationToken.getClaim(GIVEN_NAME)
        val lastnameClaim = authenticationToken.getClaim(FAMILY_NAME)
        val emailClaim = authenticationToken.getClaim(EMAIL)
        val userGroupsClaim = authenticationToken.getClaimList(GD_USER_GROUPS)

        return client.getUserByAuthenticationId(organization.id, subClaim)
            .flatMap { user ->
                logMessage("Checking for user update", "running", organization.id)
                if (userDetailsChanged(user, firstnameClaim, lastnameClaim, emailClaim, userGroupsClaim)) {
                    logMessage("User details changed, patching", "running", organization.id)
                    user.firstname = firstnameClaim
                    user.lastname = lastnameClaim
                    user.email = emailClaim
                    user.userGroups = userGroupsClaim
                    client.patchUser(organization.id, user)
                } else {
                    logMessage("User not changed, skipping update", "finished", organization.id)
                    Mono.just(user)
                }
            }.switchIfEmpty {
                logMessage("Creating user", "running", organization.id)
                client.createUser(
                    organization.id,
                    subClaim,
                    firstnameClaim,
                    lastnameClaim,
                    emailClaim,
                    userGroupsClaim ?: emptyList()
                ).doOnSuccess { provisionedUser ->
                    logMessage("User ${provisionedUser.id} created in organization", "finished", organization.id)
                }
            }
    }

    /**
     * Thrown when OAuth2AuthenticationToken is missing mandatory claims.
     */
    class MissingMandatoryClaimsException(missingClaims: List<String>) : ResponseStatusException(
        HttpStatus.UNAUTHORIZED,
        "Authorization failed. Missing mandatory claims: $missingClaims"
    )

    private fun checkMandatoryClaims(authenticationToken: OAuth2AuthenticationToken, organizationId: String) {
        val missingClaims = mandatoryClaims.filter { it !in authenticationToken.principal.attributes }
        if (missingClaims.isNotEmpty()) {
            logMessage("Authentication token is missing mandatory claim(s): $missingClaims", "error", organizationId)
            throw MissingMandatoryClaimsException(missingClaims)
        }
    }

    private fun userDetailsChanged(
        user: User,
        firstname: String,
        lastname: String,
        email: String,
        userGroups: List<String>?
    ): Boolean {
        val userGroupsChanged = userGroups != null && user.userGroups?.equalsIgnoreOrder(userGroups) == false
        return user.firstname != firstname || user.lastname != lastname || user.email != email || userGroupsChanged
    }

    private fun logMessage(message: String, state: String, organizationId: String) {
        logger.logInfo {
            withMessage { message }
            withAction("JIT")
            withState(state)
            withOrganizationId(organizationId)
        }
    }

    private fun <T> List<T>.equalsIgnoreOrder(other: List<T>) = this.size == other.size && this.toSet() == other.toSet()

    companion object Claims {
        const val GD_USER_GROUPS = "urn.gooddata.user_groups"
        val mandatoryClaims = setOf(GIVEN_NAME, FAMILY_NAME, EMAIL)
    }
}
