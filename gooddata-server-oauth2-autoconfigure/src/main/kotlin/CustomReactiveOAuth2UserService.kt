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
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.web.server.ResponseStatusException
import reactor.core.publisher.Mono

/**
 * Custom implementation of [DefaultReactiveOAuth2UserService] that introduces OAuth2User validation.
 * If the validation is not successful the authentication should fail with status UNAUTHORIZED.
 * Without this custom implementation, the authentication could fail with INTERNAL_SERVER_ERROR, when OAuth2User object
 * is not valid.
 */
class CustomReactiveOAuth2UserService(
    private val auditClient: AuthenticationAuditClient
) : DefaultReactiveOAuth2UserService() {
    @Override
    override fun loadUser(userRequest: OAuth2UserRequest): Mono<OAuth2User> {
        return super.loadUser(userRequest)
            .flatMap { user ->
                OAuth2UserValidator(auditClient).validateUser(userRequest, user)
            }
    }
}

/**
 * OAuth2UserValidator that validates the user name attribute.
 * The OAuth2User is considered invalid if user name attribute is not present or empty.
 */
class OAuth2UserValidator(
    private val auditClient: AuthenticationAuditClient
) {
    val logger = KotlinLogging.logger {}
    fun validateUser(userRequest: OAuth2UserRequest, user: OAuth2User): Mono<OAuth2User> {
        return Mono.just(user).flatMap { oauthUser ->
            val userNameAttrName = userRequest.clientRegistration.providerDetails.userInfoEndpoint.userNameAttributeName
            val userNameAttribute = oauthUser.attributes[userNameAttrName] as String?

            if (userNameAttribute.isNullOrEmpty()) {
                val errorMessage = "Authentication failed! Required \"user name\" attribute name in UserInfoEndpoint " +
                    "contains invalid value for Client Registration. Client ID: " +
                    userRequest.clientRegistration.clientId

                logger.logInfo {
                    withMessage { errorMessage }
                    withAction("Process user Authentication")
                    withState("failure")
                }

                return@flatMap getOrganizationFromContext()
                    .flatMap { organization ->
                        auditClient.recordLoginFailure(
                            orgId = organization.id,
                            userId = "",
                            source = null,
                            sessionContextType = AuthMethod.OIDC,
                            sessionContextIdentifier = userRequest.clientRegistration.clientId,
                            errorCode = "INVALID_USERNAME_ATTRIBUTE",
                            details = mapOf("errorMessage" to errorMessage)
                        )
                    }
                    .then(Mono.error(
                        ResponseStatusException(
                            HttpStatus.UNAUTHORIZED,
                            "Authorization failed, \"user name\" attribute - $userNameAttrName contains invalid " +
                                "value! Please check your Client Registration settings."
                        )
                    ))
            } else {
                Mono.just(oauthUser)
            }
        }
    }
}
