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
package com.gooddata.oauth2.server.servlet

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock
import com.github.tomakehurst.wiremock.core.WireMockConfiguration
import com.gooddata.oauth2.server.common.CaffeineJwkCache
import com.nimbusds.jose.jwk.JWKMatcher
import com.nimbusds.jose.jwk.JWKSelector
import net.javacrumbs.jsonunit.core.util.ResourceUtils
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import strikt.api.expect
import strikt.assertions.isEqualTo

internal class SimpleRemoteJwkSourceTest {

    lateinit var jwkSource: SimpleRemoteJwkSource

    @BeforeEach
    internal fun setUp() {
        jwkSource = SimpleRemoteJwkSource(
            jwkSetUri = "http://localhost:${wireMockServer.port()}/dex/keys",
            jwkCache = CaffeineJwkCache()
        )
    }

    @Test
    fun get() {
        wireMockServer
            .stubFor(
                WireMock.get(WireMock.urlEqualTo("/dex/keys"))
                    .willReturn(
                        WireMock.aResponse().withBody(ResourceUtils.resource("keySet.json").readText())
                    )
            )

        val jwks = jwkSource.get(JWKSelector(JWKMatcher.Builder().build()), null)

        expect {
            that(jwks).and {
                get { size }.isEqualTo(2)
                get { this[0].keyID }.isEqualTo("mjMcdK6mERvJ9wX6aXlUK")
                get { this[1].keyID }.isEqualTo("uRmVk7qvcuQ4hfxi2aCN8")
            }
        }
    }

    companion object {
        private val wireMockServer = WireMockServer(WireMockConfiguration().dynamicPort()).apply {
            start()
        }

        @AfterAll
        @JvmStatic
        fun cleanUp() {
            wireMockServer.stop()
        }
    }
}
