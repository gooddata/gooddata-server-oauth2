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

import com.nimbusds.jose.jwk.JWKSet
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import strikt.api.expectThat
import strikt.assertions.isSameInstanceAs

class CaffeineJwkCacheTest {

    lateinit var cache: JwkCache

    @BeforeEach
    internal fun setUp() {
        cache = CaffeineJwkCache()
    }

    @Test
    fun get() {
        val uncachedJwkSet = cache.get("SOME_URI") { JWKSet() }
        val cachedJwkSet = cache.get("SOME_URI") { JWKSet() }

        expectThat(cachedJwkSet).isSameInstanceAs(uncachedJwkSet)
    }
}
