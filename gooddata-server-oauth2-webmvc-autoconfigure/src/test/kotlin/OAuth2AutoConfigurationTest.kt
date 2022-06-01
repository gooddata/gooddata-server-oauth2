/*
 * Copyright 2021 GoodData Corporation
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
import com.ninjasquad.springmockk.MockkBean
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.EnableAutoConfiguration
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureWebMvc
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository
import org.springframework.test.context.TestPropertySource
import org.springframework.test.context.junit.jupiter.SpringExtension
import org.springframework.web.client.RestTemplate
import strikt.api.expectThat
import strikt.assertions.isEqualTo
import strikt.assertions.isNotNull
import kotlin.reflect.KProperty1
import kotlin.reflect.full.memberProperties
import kotlin.reflect.jvm.isAccessible

private const val TEST_READ_TIMEOUT = 10
private const val TEST_CONNECT_TIMEOUT = 20

@TestPropertySource(
    properties = [
        "spring.application.name=test",
        "spring.security.oauth2.client.http.readTimeoutMillis=$TEST_READ_TIMEOUT",
        "spring.security.oauth2.client.http.connectTimeoutMillis=$TEST_CONNECT_TIMEOUT"
    ]
)
@ExtendWith(SpringExtension::class)
@EnableAutoConfiguration
@AutoConfigureWebMvc
internal class OAuth2AutoConfigurationTest {

    @Autowired
    var cookieService: CookieService? = null

    @Autowired
    var authorizedClientRepository: OAuth2AuthorizedClientRepository? = null

    @Autowired
    var clientRegistrationRepository: ClientRegistrationRepository? = null

    @Autowired
    var restTemplate: RestTemplate? = null

    @MockkBean
    lateinit var authenticationStoreClient: AuthenticationStoreClient

    @MockkBean
    lateinit var userContextHolder: UserContextHolder

    @Test
    fun `context loads`() {
        expectThat(cookieService).isNotNull()
        expectThat(authorizedClientRepository).isNotNull()
        expectThat(clientRegistrationRepository).isNotNull()
        expectThat(restTemplate).isNotNull()
    }

    @Test
    fun `restTemplate has proper timeouts set`() {
        val requestFactory = restTemplate?.requestFactory!!

        val readTimeout: Int = getFieldValue("readTimeout", requestFactory)
        expectThat(readTimeout).isEqualTo(TEST_READ_TIMEOUT)
        val connectTimeout: Int = getFieldValue("connectTimeout", requestFactory)
        expectThat(connectTimeout).isEqualTo(TEST_CONNECT_TIMEOUT)
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T, R : Any> getFieldValue(fieldName: String, instance: R): T {
        val field = instance::class.memberProperties.find { it.name == fieldName } as KProperty1<R, *>
        field.isAccessible = true
        return field.get(instance) as T
    }
}
