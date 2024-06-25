/*
 * Copyright 2022 GoodData Corporation
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

import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes

/**
 * Thrown when some error related to JWK occurs.
 * @param[message] exception message
 * @param[cause] exception cause
 */
class JwkException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

/**
 * Thrown when Jwt validation failed.
 */
class JwtVerificationException(message: String = invalidClaimsMessage()) : OAuth2AuthenticationException(
    OAuth2Error(
        OAuth2ErrorCodes.INVALID_TOKEN,
        message,
        "https://tools.ietf.org/html/rfc6750#section-3.1"
    )
) {
    companion object {
        private const val EMPTY_STRING = ""
        private const val INVALID_CLAIMS_MESSAGE = "The JWT contains invalid claims%s."

        fun invalidClaimsMessage(invalidClaims: List<String> = emptyList()): String {
            val claims = if (invalidClaims.isNotEmpty()) {
                invalidClaims.joinToString(prefix = ": [", postfix = "]")
            } else {
                EMPTY_STRING
            }
            return INVALID_CLAIMS_MESSAGE.format(claims)
        }
    }
}

/**
 * Thrown when Jwt token expired.
 */
class JwtExpiredException : OAuth2AuthenticationException(
    OAuth2Error(
        OAuth2ErrorCodes.INVALID_TOKEN,
        "The JWT is expired.",
        "https://tools.ietf.org/html/rfc6750#section-3.1"
    )
)

/**
 * Thrown when Jwt is disabled by logout.
 */
class JwtDisabledException : OAuth2AuthenticationException(
    OAuth2Error(
        OAuth2ErrorCodes.INVALID_TOKEN,
        "The JWT is disabled by logout / logout all.",
        "https://tools.ietf.org/html/rfc6750#section-3.1"
    )
)

/**
 * Thrown when Jwt cannot be decoded
 */
class JwtDecodeException : OAuth2AuthenticationException(
    OAuth2Error(
        OAuth2ErrorCodes.INVALID_TOKEN,
        "We are unable to decode JWT.",
        "https://tools.ietf.org/html/rfc6750#section-3.1"
    )
)

class JwtSignatureException : OAuth2AuthenticationException(
    OAuth2Error(
        OAuth2ErrorCodes.INVALID_TOKEN,
        "We are unable to verify signature.",
        "https://tools.ietf.org/html/rfc6750#section-3.1"
    )
)
