/*
 * Copyright 2026 GoodData Corporation
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

import org.junit.jupiter.api.Test
import org.springframework.http.client.reactive.ClientHttpConnector
import org.springframework.web.reactive.function.client.ExchangeFunction
import org.springframework.web.reactive.function.client.WebClient
import reactor.netty.http.client.HttpClient
import reactor.netty.transport.ProxyProvider
import strikt.api.expectThat
import strikt.assertions.isEqualTo
import strikt.assertions.isFalse
import strikt.assertions.isNotNull
import strikt.assertions.isTrue
import kotlin.reflect.KProperty1
import kotlin.reflect.full.memberProperties
import kotlin.reflect.jvm.isAccessible

class ReactiveCommunicationClientsConfigurationTest {

    private val httpProperties = HttpProperties(
        readTimeoutMillis = 10_000,
        connectTimeoutMillis = 30_000,
        connectionIdleTimeoutMillis = 300_000,
    )

    @Test
    fun `customWebClient is not configured with a proxy when no JVM proxy system properties are set`() {
        withSystemProperties(emptyMap()) {
            val webClient = ReactiveCommunicationClientsConfiguration(httpProperties).customWebClient()

            expectThat(webClient.httpClient().configuration().hasProxy()).isFalse()
        }
    }

    @Suppress("DEPRECATION") // ProxyProvider.getAddress has no non-deprecated replacement in Reactor Netty 1.2.x
    @Test
    fun `customWebClient picks up the standard JVM https proxy system properties`() {
        withSystemProperties(
            mapOf(
                "https.proxyHost" to PROXY_HOST,
                "https.proxyPort" to PROXY_PORT.toString(),
            )
        ) {
            val webClient = ReactiveCommunicationClientsConfiguration(httpProperties).customWebClient()
            val config = webClient.httpClient().configuration()

            expectThat(config.hasProxy()).isTrue()
            val provider = config.proxyProviderSupplier()!!.get()
            expectThat(provider).isNotNull().and {
                get { type }.isEqualTo(ProxyProvider.Proxy.HTTP)
                get { address.get().hostString }.isEqualTo(PROXY_HOST)
                get { address.get().port }.isEqualTo(PROXY_PORT)
            }
        }
    }

    private fun WebClient.httpClient(): HttpClient {
        val exchangeFunction: ExchangeFunction = readField("exchangeFunction", this)
        val connector: ClientHttpConnector = readField("connector", exchangeFunction)
        return readField("httpClient", connector)
    }

    private fun withSystemProperties(properties: Map<String, String>, block: () -> Unit) {
        val previous = properties.keys.associateWith { System.getProperty(it) }
        try {
            properties.forEach { (key, value) -> System.setProperty(key, value) }
            block()
        } finally {
            previous.forEach { (key, value) ->
                if (value == null) System.clearProperty(key) else System.setProperty(key, value)
            }
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T, R : Any> readField(fieldName: String, instance: R): T {
        val field = instance::class.memberProperties.find { it.name == fieldName } as KProperty1<R, *>
        field.isAccessible = true
        return field.get(instance) as T
    }

    companion object {
        private const val PROXY_HOST = "proxy.example.com"
        private const val PROXY_PORT = 8443
    }
}
