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
package com.gooddata.oauth2.server

import io.mockk.mockk
import org.junit.jupiter.api.Test
import org.springframework.web.cors.CorsConfiguration
import strikt.api.expectThat
import strikt.assertions.isEqualTo
import java.net.URI

internal class AppLoginWebFilterRedirectTest {

    val redirectInProperties = "https://example.com"
    val filter = AppLoginRedirectProcessor(mockk(), URI(redirectInProperties))

    @Test
    fun `basic positive redirect samples`() {
        expectRedirect("https://cotoje-connect.com:1234/bla?query=123", "https://cotoje-connect.com:1234")
        expectRedirect("https://b.l.a.cotoje-connect.com:1234", "https://*.cotoje-connect.com:1234")
        expectRedirect("https://bla.cotoje-connect.com:1234", "https://*.cotoje-connect.com:1234")
        expectRedirect("https://cotoje.b.l.a.connect.com:1234", "https://cotoje.*.connect.com:1234")
        expectRedirect("https://cotoje.bla.connect.com:1234", "https://cotoje.*.connect.com:1234")
        expectRedirect("https://cotoje.connect.com:1234", "https://cotoje*.connect.com:1234")
        expectRedirect("https://cotoje.connect.com:1234", "*")
    }

    @Test
    fun `basic negative matching samples`() {
        expectCannotRedirect("https://cotoje-connect.com", "https://cotoje-connect.com:1234")
        expectCannotRedirect("cotoje-connect.com:1234", "https://cotoje-connect.com:1234")
    }

    @Test
    fun `WHEN at least one sample matches regardless ordering THEN redirect is allowed`() {
        val laboratoryMouse = "https://notojo.cotoje-connect.com"
        expectRedirect(laboratoryMouse, listOf(
            "https://cotoje.connect.com",
            "https://*.cotoje-connect.com",
        ))
        expectRedirect(laboratoryMouse, listOf(
            "https://*.cotoje-connect.com",
            "https://cotoje.connect.com",
        ))
    }

    @Test
    fun `WHEN all patterns do not match THEN redirect is not allowed`() {
        expectCannotRedirect("https://neni.to.tam.cz", listOf(
            "https://cotoje.connect.com:1234",
            "https://*.cotoje-connect.com:1234",
        ))
    }

    @Test
    fun `WHEN asterisk pattern is set THEN redirect is allowed for any uri`() {
        expectRedirect("https://vopravdu.hvezdicka.funguje.com", "*")
        expectRedirect("https://cokoliv.funguje.com:1234/neco?parameter=123", "*")
    }

    @Test
    fun `WHEN at least one sample matches THEN redirect is allowed`() {
        expectRedirect("https://notojo.cotoje-connect.com", listOf(
            "https://cotoje.connect.com",
            "https://*.cotoje-connect.com",
        ))
    }

    @Test
    fun `WHEN allowed redirect is set on the property level THEN redirect is allowed despite anything`() {
        expectRedirect(redirectInProperties, listOf(
            "https://tojedno.com:1234",
            "https://*.to-taky-jedno-co-je-tady.com:1234",
        ))
    }

    @Test
    fun `WHEN allowed redirect with path is set on the property level THEN redirect is allowed despite anything`() {
        expectRedirect("$redirectInProperties/cesta/nekam", listOf(
            "https://tojedno.com:1234",
            "https://*.to-taky-jedno-co-je-tady.com:1234",
        ))
    }

    @Test
    fun `WHEN the uri is local and starts with slash THEN redirect is allowed`() {
        expectRedirect("/lokalni/cotojecko", listOf(
            "https://cotoje-connect.com:1234",
            "https://*.cotoje-connect.com:1234",
        ))
    }

    @Test
    fun `WHEN the uri is local and doesn't start with slash THEN redirect is not allowed`() {
        expectCannotRedirect("lokalni/cotojecko/ale/bez/lomitka/na/zacatku", listOf(
            "https://cotoje-connect.com:1234",
            "https://*.cotoje-connect.com:1234",
        ))
    }

    fun expectRedirect(uri: String, pattern: String) {
        expectCanRedirect(true, uri, listOf(pattern))
    }

    fun expectRedirect(uri: String, patterns: List<String>) {
        expectCanRedirect(true, uri, patterns)
    }

    fun expectCannotRedirect(uri: String, patterns: List<String>) {
        expectCanRedirect(false, uri, patterns)
    }

    fun expectCannotRedirect(uri: String, pattern: String) {
        expectCanRedirect(false, uri, listOf(pattern))
    }

    fun expectCanRedirect(expected: Boolean, uri: String, patterns: List<String>) {
        val result = filter.canRedirect(URI(uri), CorsConfiguration().also {
            it.allowedOriginPatterns = patterns
        })

        expectThat(result).isEqualTo(expected)
    }
}
