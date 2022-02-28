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
package com.gooddata.oauth2.server.reactive

import com.gooddata.oauth2.server.common.AuthenticationStoreClient
import com.gooddata.oauth2.server.common.CaffeineJwkCache
import com.gooddata.oauth2.server.common.JwkCache
import com.ninjasquad.springmockk.MockkBean
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.EnableAutoConfiguration
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebFlux
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.test.context.TestPropertySource
import org.springframework.test.context.junit.jupiter.SpringExtension
import strikt.api.expectThat
import strikt.assertions.isA
import strikt.assertions.isNotNull

@TestPropertySource(properties = ["spring.application.name=test"])
@ExtendWith(SpringExtension::class)
@EnableAutoConfiguration
@AutoConfigureWebFlux
internal abstract class ServerOAuth2AutoConfigurationTest {

    @Autowired
    var cookieService: ReactiveCookieService? = null

    @Autowired
    var authorizedClientRepository: ServerOAuth2AuthorizedClientRepository? = null

    @Autowired
    var clientRegistrationRepository: ReactiveClientRegistrationRepository? = null

    @Autowired
    var springSecurityFilterChain: SecurityWebFilterChain? = null

    @Autowired
    var jwkCache: JwkCache? = null

    @MockkBean
    lateinit var authenticationStoreClient: AuthenticationStoreClient

    @MockkBean
    lateinit var userContextHolder: UserContextHolder<*>

    @Test
    fun `context loads`() {
        expectThat(cookieService).isNotNull()
        expectThat(authorizedClientRepository).isNotNull()
        expectThat(clientRegistrationRepository).isNotNull()
        expectThat(springSecurityFilterChain).isNotNull()
    }

    abstract fun checkCache()
}

internal class ProvidedCustomCacheServerOAuth2AutoConfigurationTest : ServerOAuth2AutoConfigurationTest() {

    override fun checkCache() {
        expectThat(jwkCache).isA<CaffeineJwkCache>()
    }
}

internal class CustomJwkCacheServerOAuth2AutoConfigurationTest : ServerOAuth2AutoConfigurationTest() {

    @MockkBean
    lateinit var myJwkCache: JwkCache

    override fun checkCache() {
        expectThat(jwkCache).not().isA<CaffeineJwkCache>()
    }
}
