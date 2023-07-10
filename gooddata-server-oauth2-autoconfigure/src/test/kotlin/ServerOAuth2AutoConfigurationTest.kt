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
package com.gooddata.oauth2.server

import com.ninjasquad.springmockk.MockkBean
import io.netty.channel.ChannelOption
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.EnableAutoConfiguration
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebFlux
import org.springframework.http.client.reactive.ClientHttpConnector
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.test.context.TestPropertySource
import org.springframework.test.context.junit.jupiter.SpringExtension
import org.springframework.web.client.RestTemplate
import org.springframework.web.reactive.function.client.ExchangeFunction
import org.springframework.web.reactive.function.client.WebClient
import reactor.netty.http.client.HttpClient
import reactor.netty.resources.ConnectionProvider
import reactor.netty.resources.ConnectionProvider.Builder
import strikt.api.expectThat
import strikt.assertions.isA
import strikt.assertions.isEqualTo
import strikt.assertions.isNotNull
import java.time.Duration
import kotlin.reflect.KProperty1
import kotlin.reflect.full.memberProperties
import kotlin.reflect.jvm.isAccessible

private const val TEST_READ_TIMEOUT = 10
private const val TEST_CONNECT_TIMEOUT = 20
private const val TEST_IDLE_TIMEOUT = 300

@TestPropertySource(
    properties = [
        "spring.application.name=test",
        "spring.security.oauth2.client.http.readTimeoutMillis=$TEST_READ_TIMEOUT",
        "spring.security.oauth2.client.http.connectTimeoutMillis=$TEST_CONNECT_TIMEOUT",
        "spring.security.oauth2.client.http.connectionIdleTimeoutMillis=$TEST_IDLE_TIMEOUT",
    ]
)
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

    @Autowired
    var restTemplate: RestTemplate? = null

    @Autowired
    var webClient: WebClient? = null

    @MockkBean
    lateinit var authenticationStoreClient: AuthenticationStoreClient

    @MockkBean
    lateinit var userContextHolder: UserContextHolder<*>

    @MockkBean
    lateinit var reactorUserContextProvider: ReactorUserContextProvider

    @Test
    fun `context loads`() {
        expectThat(cookieService).isNotNull()
        expectThat(authorizedClientRepository).isNotNull()
        expectThat(clientRegistrationRepository).isNotNull()
        expectThat(springSecurityFilterChain).isNotNull()
        expectThat(restTemplate).isNotNull()
    }

    @Test
    fun `proper http timeouts are set`() {
        // restTemplate
        val requestFactory = restTemplate?.requestFactory!!

        val readTimeout: Int = getFieldValue("readTimeout", requestFactory)
        expectThat(readTimeout).isEqualTo(TEST_READ_TIMEOUT)
        val connectTimeout: Int = getFieldValue("connectTimeout", requestFactory)
        expectThat(connectTimeout).isEqualTo(TEST_CONNECT_TIMEOUT)

        // webClient
        val exFunc: ExchangeFunction = getFieldValue("exchangeFunction", webClient!!)
        val connector: ClientHttpConnector = getFieldValue("connector", exFunc)
        val httpClient: HttpClient = getFieldValue("httpClient", connector)
        val connectionProvider: ConnectionProvider = httpClient.configuration().connectionProvider()
        val builder: Builder = connectionProvider.mutate()!!
        val maxIdleTime: Duration = getFieldValue("maxIdleTime", builder)

        expectThat(httpClient.configuration().responseTimeout()?.toMillis()).isEqualTo(TEST_READ_TIMEOUT.toLong())
        expectThat(httpClient.configuration().options()[ChannelOption.CONNECT_TIMEOUT_MILLIS]).isEqualTo(
            TEST_CONNECT_TIMEOUT
        )
        expectThat(maxIdleTime.toMillis()).isEqualTo(TEST_IDLE_TIMEOUT.toLong())
    }

    abstract fun checkCache()

    @Suppress("UNCHECKED_CAST")
    private fun <T, R : Any> getFieldValue(fieldName: String, instance: R): T {
        val field = instance::class.memberProperties.find { it.name == fieldName } as KProperty1<R, *>
        field.isAccessible = true
        return field.get(instance) as T
    }
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
