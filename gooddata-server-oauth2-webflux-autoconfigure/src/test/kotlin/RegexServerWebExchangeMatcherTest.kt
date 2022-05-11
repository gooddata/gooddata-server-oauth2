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

import com.gooddata.oauth2.server.common.OPEN_API_SCHEMA_PATTERN
import org.junit.jupiter.api.Test
import org.springframework.http.HttpMethod
import strikt.api.expectThat
import strikt.assertions.isFalse
import strikt.assertions.isTrue

class RegexServerWebExchangeMatcherTest {
    private val matcher = RegexServerWebExchangeMatcher(OPEN_API_SCHEMA_PATTERN.toRegex(), HttpMethod.GET)

    @Test
    fun `schemas without version`() {
        expectThat(
            matcher.matches(HttpMethod.GET, "/api/schemas/service")
        ).isTrue()
    }

    @Test
    fun `schemas with v1 version`() {
        expectThat(
            matcher.matches(HttpMethod.GET, "/api/v1/schemas/service")
        ).isTrue()
    }

    @Test
    fun `unknown path`() {
        expectThat(
            matcher.matches(HttpMethod.GET, "/api/unknown")
        ).isFalse()
    }

    @Test
    fun `wrong HTTP protocol`() {
        expectThat(
            matcher.matches(HttpMethod.POST, "/api/v1/schemas/service")
        ).isFalse()
    }
}
