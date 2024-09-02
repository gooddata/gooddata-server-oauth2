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
import com.nimbusds.jwt.JWTClaimNames
import com.nimbusds.openid.connect.sdk.claims.PersonClaims
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
        const val JWT_NAME_MAX_LENGTH = 511
        private const val STRING_255_REGEX = "^(?!\\.)[.A-Za-z0-9_-]{1,255}\$"
        private val string255Regex = Regex(STRING_255_REGEX)

        // These headers are potential security vulnerabilities for header injection
        private val notAllowedHeaders = listOf("jku", "x5u", "jwk", "x5c")
        private val mandatoryAttributes = listOf(
            JWTClaimNames.SUBJECT,
            JWTClaimNames.ISSUED_AT,
            JWTClaimNames.EXPIRATION_TIME
        )
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

        validateMandatoryClaims(token).let { validationErrors.addAll(it) }
        validateNotAllowedHeaders(token).let { validationErrors.addAll(it) }
        validateMaxLength(token, PersonClaims.NAME_CLAIM_NAME, JWT_NAME_MAX_LENGTH)?.let { validationErrors.add(it) }
        validateRegex(token, JWTClaimNames.JWT_ID, string255Regex)?.let { validationErrors.add(it) }
        validateRegex(token, JWTClaimNames.SUBJECT, string255Regex)?.let { validationErrors.add(it) }

        return if (validationErrors.isEmpty()) {
            OAuth2TokenValidatorResult.success()
        } else {
            OAuth2TokenValidatorResult.failure(validationErrors)
        }
    }

    private fun representJwtWithId(jwt: Jwt) = jwt.headers["kid"] != null

    private fun validateMandatoryClaims(token: Jwt): List<OAuth2Error> =
        mandatoryAttributes
            .filter { !token.claims.containsKey(it) }
            .map { claim ->
                OAuth2Error(
                    "missing_mandatory_attribute",
                    "Jwt does not contain mandatory attribute \"${claim}\"",
                    null
                )
            }

    private fun validateNotAllowedHeaders(token: Jwt): List<OAuth2Error> =
        notAllowedHeaders
            .filter { token.headers.containsKey(it) }
            .map { header ->
                OAuth2Error(
                    "${header}_not_allowed",
                    "Jwt contains not allowed header parameter \"${header}\".",
                    null
                )
            }

    private fun validateMaxLength(token: Jwt, claim: String, maxLength: Int): OAuth2Error? =
        token.claims[claim]
            ?.let { it as String }
            ?.let {
                if (it.length > maxLength) {
                    OAuth2Error(
                        "${claim}_max_length",
                        "Jwt contains \"${claim}\" bigger than $maxLength characters.",
                        null
                    )
                } else {
                    null
                }
            }

    private fun validateRegex(token: Jwt, claim: String, regex: Regex): OAuth2Error? =
        token.claims[claim]
            ?.let { it as String }
            ?.let {
                if (!regex.matches(it)) {
                    OAuth2Error(
                        "${claim}_regex",
                        "Jwt contains \"${claim}\" that does not satisfy given regex pattern.",
                        null
                    )
                } else {
                    null
                }
            }
}
