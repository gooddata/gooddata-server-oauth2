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

import mu.KLogger
import java.util.Base64

/**
 * Log cookie name and value
 */
fun KLogger.debugCookie(name: String, value: String) {
    debug { "cookie_name=$name cookie_value=${value.simplify()}" }
}

/**
 * Log JWT token stored in cookie
 */
fun KLogger.debugToken(name: String, token: String) {
    debug { "token_name=$name ${tokenDetails(token)}" }
}

/**
 * Parse JWT token, convert headers and claims to JSON like string
 */
private fun tokenDetails(token: String): String {
    val parts = token.split('.')
    val headers = parts[0].fromBase64().simplify()
    val claims = parts[1].fromBase64().simplify()
    return "token_headers=$headers token_claims=$claims"
}

/**
 * Replace '"' by "'" to avoid escaping in logging
 */
private fun String.simplify(): String = replace('"', '\'')

/**
 * Read text from Base64 string
 */
private fun String.fromBase64(): String = String(Base64.getDecoder().decode(toByteArray()))
