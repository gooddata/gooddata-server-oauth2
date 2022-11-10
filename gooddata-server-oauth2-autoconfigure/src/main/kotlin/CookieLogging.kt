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

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import com.gooddata.api.logging.logDebug
import mu.KLogger
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64

private val SENSITIVE_KEYS = listOf("cid", "jti", "kid", "uid")
private val TIME_KEYS = listOf("auth_time", "exp", "iat")
private const val REMOVE_CHARS_COUNT = 6
private const val SUFFIX = "***"
private val FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
private val objectMapper = ObjectMapper()

/**
 * Log JWT token stored in cookie
 */
fun KLogger.debugToken(cookieName: String, tokenType: String, tokenValue: String) {
    logDebug { withMessage { "cookie_name=$cookieName token_type=$tokenType ${tokenDetails(tokenValue)}" } }
}

/**
 * Parse JWT token, convert headers and claims to JSON like string
 */
private fun tokenDetails(token: String): String {
    val parts = token.split('.')
    val headers = formatJsonForLogging(parts[0].fromBase64())
    val claims = formatJsonForLogging(parts[1].fromBase64())
    return "headers=${headers.simplify()} claims=${claims.simplify()}"
}

internal fun formatJsonForLogging(tokenJson: String): String {
    val token: ObjectNode = objectMapper.readTree(tokenJson).deepCopy()
    SENSITIVE_KEYS.filter { token.has(it) }.forEach { sensitiveKey ->
        val value = token.get(sensitiveKey).asText()
        token.put(sensitiveKey, replaceLast(value, REMOVE_CHARS_COUNT, SUFFIX))
    }
    TIME_KEYS.filter { token.has(it) }.forEach { timeKey ->
        val seconds = token.get(timeKey).asLong()
        token.put(timeKey, secondsToDateTimeString(seconds))
    }
    return token.toString()
}

/**
 * Format Unix time to string
 */
@Suppress("TooGenericExceptionCaught")
internal fun secondsToDateTimeString(seconds: Long): String =
    try {
        LocalDateTime.ofEpochSecond(seconds, 0, ZoneOffset.UTC).format(FORMATTER)
    } catch (exc: Throwable) {
        seconds.toString()
    }

/**
 * Replace last characters by text
 */
internal fun replaceLast(value: String, count: Int, suffix: String): String = value.dropLast(count).plus(suffix)

/**
 * Replace '"' by "'" to avoid escaping in logging
 */
private fun String.simplify(): String = replace('"', '\'')

/**
 * Read text from Base64 string
 */
private fun String.fromBase64(): String = String(Base64.getDecoder().decode(toByteArray()))
