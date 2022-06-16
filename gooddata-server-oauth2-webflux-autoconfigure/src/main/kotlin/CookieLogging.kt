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
package com.gooddata.oauth2.server.reactive

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import mu.KLogger
import java.util.Base64

private val SENSITIVE_KEYS = listOf("cid", "jti", "kid", "uid")
private const val REMOVE_CHARS_COUNT = 6
private val SUFFIX = "***"

/**
 * Log JWT token stored in cookie
 */
fun KLogger.debugToken(cookieName: String, tokenType: String, tokenValue: String) {
    debug { "cookie_name=$cookieName token_type=$tokenType ${tokenDetails(tokenValue)}" }
}

/**
 * Parse JWT token, convert headers and claims to JSON like string
 */
private fun tokenDetails(token: String): String {
    val parts = token.split('.')
    val headers = maskSensitiveValues(parts[0].fromBase64())
    val claims = maskSensitiveValues(parts[1].fromBase64())
    return "token_headers=${headers.simplify()} token_claims=${claims.simplify()}"
}

/**
 * Replace last characters of sensitive values by dots
 */
internal fun maskSensitiveValues(tokenJson: String): String {
    val objectMapper = ObjectMapper()
    val token: ObjectNode = objectMapper.readTree(tokenJson).deepCopy()
    SENSITIVE_KEYS.forEach { sensitiveKey ->
        if (token.has(sensitiveKey)) {
            val value = token.get(sensitiveKey).asText()
            val safeValue = value.dropLast(REMOVE_CHARS_COUNT).plus(SUFFIX)
            token.put(sensitiveKey, safeValue)
        }
    }
    return token.toString()
}

/**
 * Replace '"' by "'" to avoid escaping in logging
 */
private fun String.simplify(): String = replace('"', '\'')

/**
 * Read text from Base64 string
 */
private fun String.fromBase64(): String = String(Base64.getDecoder().decode(toByteArray()))
