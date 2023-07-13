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

import com.gooddata.oauth2.server.CustomOAuth2Validator.Companion.notAllowedHeaders
import com.nimbusds.jose.JOSEObjectType
import mu.KotlinLogging
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult
import org.springframework.security.oauth2.jwt.Jwt

/**
 * Custom implementation of [OAuth2TokenValidator] which adds additional validation of [Jwt] headers.
 * [CustomOAuth2Validator] searches through [Jwt] headers for [notAllowedHeaders] that are generally considered as
 * potential security risks and could be misused for JWT header injection.
 */
class CustomOAuth2Validator : OAuth2TokenValidator<Jwt> {

    companion object {
        // These headers are potential security vulnerabilities for header injection
        private val notAllowedHeaders = listOf("jku", "x5u", "jwk", "x5c")
        private val mandatoryAttributes = listOf("sub", "name", "iat", "exp")
    }

    /**
     * Checks given [Jwt] for not-allowed headers.
     * @param token to be checked for not-allowed headers
     */
    override fun validate(token: Jwt): OAuth2TokenValidatorResult {
        val validationErrors = mutableListOf<OAuth2Error>()

        if (!representJwtWithId(token)) {
            validationErrors.add(
                OAuth2Error(
                    "not_valid_jwt",
                    "Token is not a valid Jwt",
                    null
                )
            )
        }

        mandatoryAttributes.forEach { attribute ->
            if (!token.claims.containsKey(attribute)) {
                validationErrors.add(
                    OAuth2Error(
                        "missing_mandatory_attribute",
                        "Jwt does not contain mandatory attribute \"${attribute}\"",
                        null
                    )
                )
            }
        }

        notAllowedHeaders.forEach { header ->
            if (token.headers.containsKey(header)) {
                validationErrors.add(
                    OAuth2Error(
                        "${header}_not_allowed",
                        "Jwt contains not allowed header parameter \"${header}\".",
                        null
                    )
                )
            }
        }
        return if (validationErrors.isEmpty()) OAuth2TokenValidatorResult.success()
        else OAuth2TokenValidatorResult.failure(validationErrors)
    }

    private fun representJwtWithId(jwt: Jwt) =
        jwt.headers["kid"] != null && jwt.headers["typ"] == JOSEObjectType.JWT.toString()
}
