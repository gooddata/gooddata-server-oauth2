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

import com.gooddata.oauth2.server.utils.checkMandatoryClaims
import com.gooddata.oauth2.server.utils.logMessage
import com.gooddata.oauth2.server.utils.userDetailsChanged
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.core.oidc.StandardClaimNames.EMAIL
import org.springframework.security.oauth2.core.oidc.StandardClaimNames.FAMILY_NAME
import org.springframework.security.oauth2.core.oidc.StandardClaimNames.GIVEN_NAME
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import reactor.core.publisher.Mono
import reactor.kotlin.core.publisher.switchIfEmpty

class JitProvisioningAuthenticationSuccessHandler(
    private val client: AuthenticationStoreClient
) : ServerAuthenticationSuccessHandler {

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
            client.getJitProvisioningSetting(organization.id).flatMap {
                if (it.enabled) {
                    provisionUser(authenticationToken, organization, it)
                } else {
                    Mono.empty()
                }
            }
        }
    }

    private fun provisionUser(
        authenticationToken: OAuth2AuthenticationToken,
        organization: Organization,
        jitSetting: JitProvisioningSetting,
    ): Mono<User> {
        val subClaimName = organization.oauthSubjectIdClaim ?: IdTokenClaimNames.SUB
        checkMandatoryClaims(mandatoryClaims + subClaimName, authenticationToken.principal.attributes, organization.id)
        logMessage("Initiating JIT provisioning", "started", organization.id)
        val subClaim = authenticationToken.getClaim(subClaimName)
        val firstnameClaim = authenticationToken.getClaim(GIVEN_NAME)
        val lastnameClaim = authenticationToken.getClaim(FAMILY_NAME)
        val emailClaim = authenticationToken.getClaim(EMAIL)

        val userGroupsClaimName = jitSetting.userGroupsClaimName ?: GD_USER_GROUPS
        val userGroups = if (jitSetting.userGroupsScopeEnabled) {
            authenticationToken.getClaimList(userGroupsClaimName) ?: jitSetting.userGroupsDefaults
        } else {
            jitSetting.userGroupsDefaults
        }
        val shouldApplyUserGroups = (jitSetting.userGroupsScopeEnabled || jitSetting.userGroupsDefaults != null)

        return client.getUserByAuthenticationId(organization.id, subClaim)
            .flatMap { user ->
                logMessage("Checking for user update", "running", organization.id)
                if (userDetailsChanged(user, firstnameClaim, lastnameClaim, emailClaim, userGroups)) {
                    logMessage("User details changed, patching", "running", organization.id)
                    user.firstname = firstnameClaim
                    user.lastname = lastnameClaim
                    user.email = emailClaim
                    if (shouldApplyUserGroups) user.userGroups = userGroups
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
                    if (shouldApplyUserGroups) userGroups ?: emptyList() else emptyList()
                ).doOnSuccess { provisionedUser ->
                    logMessage("User ${provisionedUser.id} created in organization", "finished", organization.id)
                }
            }
    }

    companion object Claims {
        const val GD_USER_GROUPS = "urn.gooddata.user_groups"
        val mandatoryClaims = setOf(GIVEN_NAME, FAMILY_NAME, EMAIL)
    }
}
