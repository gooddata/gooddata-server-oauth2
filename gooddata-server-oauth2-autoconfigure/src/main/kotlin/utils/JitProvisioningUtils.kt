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
package com.gooddata.oauth2.server.utils

import com.gooddata.oauth2.server.User
import com.gooddata.oauth2.server.logInfo
import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.http.HttpStatus
import org.springframework.web.server.ResponseStatusException

private val logger = KotlinLogging.logger {}

/**
 * Thrown when authentication token is missing mandatory claims.
 */
class MissingMandatoryClaimsException(missingClaims: List<String>) : ResponseStatusException(
    HttpStatus.UNAUTHORIZED,
    "Authorization failed. Missing mandatory claims: $missingClaims"
)

fun checkMandatoryClaims(mandatoryClaims: Set<String>, tokenAttributes: Map<String, Any>, organizationId: String) {
    val missingClaims = mandatoryClaims.filter { it !in tokenAttributes }
    if (missingClaims.isNotEmpty()) {
        logMessage("Authentication token is missing mandatory claim(s): $missingClaims", "error", organizationId)
        throw MissingMandatoryClaimsException(missingClaims)
    }
}

fun userDetailsChanged(
    user: User,
    firstname: String,
    lastname: String,
    email: String,
    userGroups: List<String>?
): Boolean {
    val userGroupsChanged = userGroups != null && user.userGroups?.equalsIgnoreOrder(userGroups) == false
    return user.firstname != firstname || user.lastname != lastname || user.email != email || userGroupsChanged
}

fun logMessage(
    message: String,
    state: String,
    organizationId: String
) = logger.logInfo {
    withMessage { message }
    withAction("JIT")
    withState(state)
    withOrganizationId(organizationId)
}

private fun <T> List<T>.equalsIgnoreOrder(other: List<T>) = this.size == other.size && this.toSet() == other.toSet()

data class UserClaims(
    val sub: String,
    val firstname: String,
    val lastname: String,
    val email: String,
    val userGroups: List<String>?,
    val shouldApplyUserGroups: Boolean
)
