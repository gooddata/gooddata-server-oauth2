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

import kotlinx.coroutines.reactor.mono
import mu.KotlinLogging
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import reactor.core.publisher.Mono

class JitProvisioningAuthenticationSuccessHandler(
    private val client: AuthenticationStoreClient
) : ServerAuthenticationSuccessHandler {

    private val logger = KotlinLogging.logger {}

    override fun onAuthenticationSuccess(
        webFilterExchange: WebFilterExchange?,
        authentication: Authentication?
    ): Mono<Void> = Mono.justOrEmpty(authentication)
        .cast(OAuth2AuthenticationToken::class.java)
        .flatMap { provisionUser(client, it, webFilterExchange) }
        .then()

    private fun provisionUser(
        authenticationStoreClient: AuthenticationStoreClient,
        authenticationToken: OAuth2AuthenticationToken,
        webFilterExchange: WebFilterExchange?,
    ): Mono<*> {
        return mono {
            val organization = authenticationStoreClient.getOrganizationByHostname(
                webFilterExchange?.exchange?.request?.uri?.host ?: ""
            )
            if (organization.jitEnabled == true) {
                checkMandatoryClaims(authenticationToken, organization.id)
                logMessage("Initiating JIT provisioning", "started", organization.id)
                val subClaim = authenticationToken.getClaim(organization.oauthSubjectIdClaim)
                val firstnameClaim = authenticationToken.getClaim(GIVEN_NAME)
                val lastnameClaim = authenticationToken.getClaim(FAMILY_NAME)
                val emailClaim = authenticationToken.getClaim(EMAIL)
                val userGroupsClaim = authenticationToken.getClaimList(GD_USER_GROUPS)
                val user: User? = authenticationStoreClient.getUserByAuthenticationId(organization.id, subClaim)
                if (user != null) {
                    logMessage("Checking for user update", "running", organization.id)
                    if (userDetailsChanged(user, firstnameClaim, lastnameClaim, emailClaim, userGroupsClaim)) {
                        logMessage("User details changed, patching", "running", organization.id)
                        user.firstname = firstnameClaim
                        user.lastname = lastnameClaim
                        user.email = emailClaim
                        user.userGroups = userGroupsClaim
                        authenticationStoreClient.patchUser(organization.id, user)
                    } else {
                        logMessage("User not changed, skipping update", "finished", organization.id)
                    }
                } else {
                    logMessage("Creating user", "running", organization.id)
                    val provisionedUser = authenticationStoreClient.createUser(
                        organization.id,
                        subClaim,
                        firstnameClaim,
                        lastnameClaim,
                        emailClaim,
                        userGroupsClaim ?: emptyList()
                    )
                    logMessage("User ${provisionedUser.id} created in organization", "finished", organization.id)
                }
            } else {
                logMessage("JIT provisioning disabled, skipping", "finished", organization.id)
            }
        }
    }

    /**
     * Thrown when OAuth2AuthenticationToken is missing mandatory claims.
     */
    class MissingMandatoryClaimsException(missingClaims: List<String>) : OAuth2AuthenticationException(
        OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, "Missing mandatory claims: $missingClaims", null)
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
        const val GIVEN_NAME = "given_name"
        const val FAMILY_NAME = "family_name"
        const val EMAIL = "email"
        const val GD_USER_GROUPS = "gd_user_groups"
        val mandatoryClaims = setOf(GIVEN_NAME, FAMILY_NAME, EMAIL)
    }
}
