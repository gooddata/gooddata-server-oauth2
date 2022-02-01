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

import com.gooddata.oauth2.server.common.AuthenticationStoreClient
import com.gooddata.oauth2.server.common.Organization
import com.gooddata.oauth2.server.common.OrganizationCorsConfigurationSource
import io.mockk.coEvery
import io.mockk.mockk
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import strikt.api.expectThat
import strikt.assertions.isEqualTo

internal class CompositeCorsConfigurationSourceTest {

    private val client = mockk<AuthenticationStoreClient>()

    private val corsConfigurationSource = CompositeCorsConfigurationSource(
        UrlBasedCorsConfigurationSource().apply {
            GLOBAL_CORS_CONFIGURATION.forEach { (t, u) -> registerCorsConfiguration(t, u) }
        },
        OrganizationCorsConfigurationSource(client)
    )

    @BeforeEach
    internal fun setUp() {
        coEvery { client.getOrganizationByHostname(ORGANIZATION_HOST_NAME) } returns Organization(
            id = "testOrg",
            allowedOrigins = ORGANIZATION_ALLOWED_ORIGINS
        )
    }

    @ParameterizedTest
    @EnumSource(TestCorsSource::class)
    fun getOrganizationCorsConfiguration(testCorsSource: TestCorsSource) {
        val request = MockHttpServletRequest("GET", testCorsSource.requestUri)
        val corsConfiguration = corsConfigurationSource.getCorsConfiguration(request)
        expectThat(corsConfiguration?.allowedOrigins).isEqualTo(testCorsSource.allowedOrigins)
        expectThat(corsConfiguration?.allowedMethods).isEqualTo(testCorsSource.allowedMethods)
    }

    companion object {
        private const val ORGANIZATION_HOST_NAME = "localhost"
        private const val SOME_GLOBAL_PATH = "/some/global/path"
        private const val ANOTHER_GLOBAL_PATH = "/another/global/path"
        private const val GLOBAL_ALLOWED_ORIGIN = "http://localhost:1234"
        private val ORGANIZATION_ALLOWED_ORIGINS = listOf(
            "https://some.domain.com",
            "http://another:1234",
        )
        private val GLOBAL_CORS_CONFIGURATION = mapOf(
            SOME_GLOBAL_PATH to CorsConfiguration().apply {
                allowedMethods = listOf("GET")
                allowedOrigins = listOf(CorsConfiguration.ALL)
            },
            "$ANOTHER_GLOBAL_PATH/*" to CorsConfiguration().apply {
                allowedMethods = listOf("PUT")
                allowedOrigins = listOf(GLOBAL_ALLOWED_ORIGIN)
            }
        )
    }

    enum class TestCorsSource(
        val requestUri: String,
        val allowedOrigins: List<String>,
        val allowedMethods: List<String>
    ) {
        SOME_ORGANIZATION(
            "/request/uri",
            ORGANIZATION_ALLOWED_ORIGINS,
            listOf(CorsConfiguration.ALL)
        ),
        SOME_GLOBAL(
            SOME_GLOBAL_PATH,
            listOf(CorsConfiguration.ALL),
            listOf("GET")
        ),
        ANOTHER_GLOBAL(
            "$ANOTHER_GLOBAL_PATH/xxx",
            listOf(GLOBAL_ALLOWED_ORIGIN),
            listOf("PUT")
        )
    }
}
