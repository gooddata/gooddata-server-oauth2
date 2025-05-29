/*
 * Copyright 2023 GoodData Corporation
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

import com.gooddata.oauth2.server.utils.UserClaims
import com.gooddata.oauth2.server.utils.checkMandatoryClaims
import com.gooddata.oauth2.server.utils.logMessage
import com.nimbusds.jwt.JWTClaimNames
import com.nimbusds.jwt.JWTClaimNames.SUBJECT
import com.nimbusds.openid.connect.sdk.claims.PersonClaims
import io.github.oshai.kotlinlogging.KotlinLogging
import java.time.Instant
import org.springframework.http.HttpStatus
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler
import org.springframework.web.server.ResponseStatusException
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono
import reactor.kotlin.core.publisher.switchIfEmpty

/**
 * If `SecurityContext` contains [JwtAuthenticationToken] the [JwtAuthenticationProcessor] handles the
 * authentication by retrieving [Organization] by request uri host, and authenticating the user based on `Jwks`
 * configured for the given organization.
 */
class JwtAuthenticationProcessor(
    private val client: AuthenticationStoreClient,
    private val serverLogoutHandler: ServerLogoutHandler,
    private val reactorUserContextProvider: ReactorUserContextProvider,
) : AuthenticationProcessor<JwtAuthenticationToken>(reactorUserContextProvider) {

    private val logger = KotlinLogging.logger {}

    // TODO optimize organization get (performance can be improved because org is requested also during JWT decoding)
    override fun authenticate(
        authenticationToken: JwtAuthenticationToken,
        exchange: ServerWebExchange,
        chain: WebFilterChain,
    ): Mono<Void> = getOrganizationFromContext().flatMap { organization ->
        validateJwtToken(authenticationToken, organization)
    }.flatMap { organization ->
        getUserForJwtToken(exchange, chain, authenticationToken, organization).flatMap { user ->
            withUserContext(
                organization,
                user,
                resolveUserName(authenticationToken, user),
                AuthMethod.JWT,
                authenticationToken.tokenAttributeOrNull(JWTClaimNames.JWT_ID).toString(),
            ) {
                chain.filter(exchange)
            }
        }
    }

    private fun resolveUserName(token: JwtAuthenticationToken, user: User): String =
        token.tokenAttributeOrNull(PersonClaims.NAME_CLAIM_NAME)?.toString() ?: (user.name ?: user.id)

    private fun validateJwtToken(
        token: JwtAuthenticationToken,
        organization: Organization,
    ): Mono<Organization> {
        val tokenHash = hashStringWithMD5(token.token.tokenValue)
        val jwtId = token.tokenAttributeOrNull(JWTClaimNames.JWT_ID).toString()
        return client.isValidJwt(organization.id, token.name, tokenHash, jwtId).flatMap { isValid ->
            when (isValid) {
                true -> Mono.just(organization)
                false -> Mono.error(JwtDisabledException())
            }
        }
    }

    private fun getUserForJwtToken(
        exchange: ServerWebExchange,
        chain: WebFilterChain,
        authenticationToken: JwtAuthenticationToken,
        organization: Organization,
    ): Mono<User> {
        logger.info { "getUserForJwtToken ${authenticationToken.name} ${organization.id}" }
        return client.getUserById(organization.id, authenticationToken.name).switchIfEmpty {
            client.getJwtJitProvisioningSetting(organization.id).flatMap {
                if (it.enabled) {
                    provisionUser(authenticationToken, organization, it)
                } else {
                    Mono.error(
                        ResponseStatusException(
                            HttpStatus.NOT_FOUND,
                            "User with ID='${authenticationToken.name}' is not registered"
                        )
                    )
                }
            }
        }.flatMap { user ->
            val tokenIssuedAtTime = authenticationToken.tokenAttributeOrNull(JWTClaimNames.ISSUED_AT) as Instant?
            val isValidToken = isValidToken(tokenIssuedAtTime, user.lastLogoutAllTimestamp)
            logger.info {
                "getUserForJwtToken is valid $tokenIssuedAtTime ${user.lastLogoutAllTimestamp} $isValidToken"
            }
            if (!isValidToken) {
                serverLogoutHandler.logout(WebFilterExchange(exchange, chain), authenticationToken)
                    .then(Mono.error(JwtDisabledException()))
            } else {
                Mono.just(user)
            }
        }
    }

    private fun provisionUser(
        authenticationToken: JwtAuthenticationToken,
        organization: Organization,
        jitSetting: JwtJitProvisioningSetting,
    ): Mono<User> {
        logMessage("Initiating JIT provisioning", "started", organization.id)
        val claims = extractUserClaims(authenticationToken, jitSetting, organization.id)
        return client.createUser(
            organization.id,
            claims.sub,
            claims.firstname,
            claims.lastname,
            claims.email,
            claims.userGroups ?: emptyList()
        ).doOnNext {
            logMessage("JIT provisioning finished", "finished", organization.id)
        }
    }

    private fun extractUserClaims(
        authenticationToken: JwtAuthenticationToken,
        jitSetting: JwtJitProvisioningSetting,
        organizationId: String
    ): UserClaims {
        checkMandatoryClaims(mandatoryClaims, authenticationToken.tokenAttributes, organizationId)

        val sub = authenticationToken.mandatoryTokenAttribute(SUBJECT)
        var firstname = authenticationToken.tokenAttributeOrNull(GIVEN_NAME)?.toString()
        var lastname = authenticationToken.tokenAttributeOrNull(FAMILY_NAME)?.toString()
        val email = authenticationToken.mandatoryTokenAttribute(EMAIL)

        val userGroupsClaimName = jitSetting.userGroupsClaimName ?: USER_GROUPS
        val userGroups = authenticationToken.getAttributeList(userGroupsClaimName) ?: jitSetting.userGroupsDefaults

        if (firstname.isNullOrEmpty() || lastname.isNullOrEmpty()) {
            // Fallback to NAME claim if GIVEN_NAME or FAMILY_NAME are not present
            val nameClaim = authenticationToken.tokenAttributeOrNull(NAME)?.toString()
            if (nameClaim != null) {
                val names = nameClaim.split(NAME_DELIMITER, limit = 2)
                firstname = names.getOrNull(0) ?: EMPTY_NAME
                lastname = names.getOrNull(1) ?: EMPTY_NAME
            }
        }

        return UserClaims(
            sub = sub,
            firstname = firstname!!,
            lastname = lastname!!,
            email = email,
            userGroups = userGroups,
            shouldApplyUserGroups = true
        )
    }

    companion object {
        const val EMAIL = "email"
        const val NAME = "name"
        const val GIVEN_NAME = "givenName"
        const val FAMILY_NAME = "familyName"
        const val USER_GROUPS = "userGroups"
        private const val EMPTY_NAME = ""
        private const val NAME_DELIMITER = " "

        val mandatoryClaims = setOf(SUBJECT, NAME)

        private fun isValidToken(tokenIssuedAtTime: Instant?, lastLogoutAllTimestamp: Instant?): Boolean =
            lastLogoutAllTimestamp == null ||
                tokenIssuedAtTime != null && tokenIssuedAtTime.isAfter(lastLogoutAllTimestamp)

        private fun JwtAuthenticationToken.tokenAttributeOrNull(attribute: String): Any? =
            tokenAttributes.getOrDefault(attribute, null)

        private fun JwtAuthenticationToken.mandatoryTokenAttribute(claimName: String): String =
            tokenAttributes[claimName]?.toString()
                ?: throw InvalidBearerTokenException("Token does not contain $claimName claim.")

        private fun JwtAuthenticationToken.getAttributeList(attrName: String?): List<String>? =
            when (val attr = tokenAttributes.getOrDefault(attrName, null)) {
                is String -> attr.split(',')
                is List<*> -> attr.filterIsInstance<String>()
                else -> null
            }
    }
}
